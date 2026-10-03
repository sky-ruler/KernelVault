/**
 * @file KeyDerivation.cpp
 * @brief Implementation of RFC 2898 PBKDF2, HMAC-SHA256, and secure memory hygiene for kvault.
 */

#include "KeyDerivation.hpp"

#include <cstring>
#include <array>
#include <atomic>
#include <sys/random.h>
#include <cerrno>

namespace kvault {

namespace {

// ============================================================================
// Internal Cryptographic Engine: FIPS 180-4 Standard SHA-256
// ============================================================================

class Sha256Context {
public:
    Sha256Context() noexcept { reset(); }

    void reset() noexcept {
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
        m_count = 0;
        m_bufferLen = 0;
    }

    void update(const uint8_t* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            m_buffer[m_bufferLen++] = data[i];
            if (m_bufferLen == 64) {
                transform(m_buffer.data());
                m_count += 512;
                m_bufferLen = 0;
            }
        }
    }

    void finalize(std::span<uint8_t, 32> digest) noexcept {
        m_count += m_bufferLen * 8;
        m_buffer[m_bufferLen++] = 0x80;

        if (m_bufferLen > 56) {
            while (m_bufferLen < 64) {
                m_buffer[m_bufferLen++] = 0x00;
            }
            transform(m_buffer.data());
            m_bufferLen = 0;
        }

        while (m_bufferLen < 56) {
            m_buffer[m_bufferLen++] = 0x00;
        }

        for (size_t i = 0; i < 8; ++i) {
            const size_t byteIndex = 56U + i;
            const size_t shift = (7U - i) * 8U;
            m_buffer[byteIndex] = static_cast<uint8_t>((m_count >> shift) & 0xFFU);
        }
        transform(m_buffer.data());

        for (size_t i = 0; i < 8; ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>((m_state[i] >> 24) & 0xFF);
            digest[i * 4 + 1] = static_cast<uint8_t>((m_state[i] >> 16) & 0xFF);
            digest[i * 4 + 2] = static_cast<uint8_t>((m_state[i] >> 8) & 0xFF);
            digest[i * 4 + 3] = static_cast<uint8_t>(m_state[i] & 0xFF);
        }

        // Clean internal state
        KeyDerivation::secureZero(this, sizeof(*this));
    }

private:
    static inline uint32_t rotr(uint32_t x, uint32_t n) noexcept {
        return (x >> n) | (x << (32 - n));
    }

    static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
        return (x & y) ^ (~x & z);
    }

    static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static inline uint32_t sigma0(uint32_t x) noexcept {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static inline uint32_t sigma1(uint32_t x) noexcept {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static inline uint32_t gamma0(uint32_t x) noexcept {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static inline uint32_t gamma1(uint32_t x) noexcept {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transform(const uint8_t* block) noexcept {
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t w[64];
        for (size_t t = 0; t < 16; ++t) {
            w[t] = (static_cast<uint32_t>(block[t * 4 + 0]) << 24) |
                   (static_cast<uint32_t>(block[t * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[t * 4 + 2]) << 8)  |
                   (static_cast<uint32_t>(block[t * 4 + 3]));
        }
        for (size_t t = 16; t < 64; ++t) {
            w[t] = gamma1(w[t - 2]) + w[t - 7] + gamma0(w[t - 15]) + w[t - 16];
        }

        uint32_t a = m_state[0];
        uint32_t b = m_state[1];
        uint32_t c = m_state[2];
        uint32_t d = m_state[3];
        uint32_t e = m_state[4];
        uint32_t f = m_state[5];
        uint32_t g = m_state[6];
        uint32_t h = m_state[7];

        for (size_t t = 0; t < 64; ++t) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[t] + w[t];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;

        KeyDerivation::secureZero(w, sizeof(w));
    }

    std::array<uint32_t, 8> m_state;
    uint64_t m_count;
    std::array<uint8_t, 64> m_buffer;
    size_t m_bufferLen;
};

void internalSha256(const uint8_t* data, size_t len, std::span<uint8_t, 32> outDigest) {
    Sha256Context ctx;
    ctx.update(data, len);
    ctx.finalize(outDigest);
}

} // namespace

// ============================================================================
// Public Interface Implementations
// ============================================================================

void KeyDerivation::secureZero(void* ptr, size_t length) noexcept {
    if (!ptr || length == 0) return;

    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (length--) {
        *p++ = 0;
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

bool KeyDerivation::generateSalt(std::span<uint8_t, SALT_SIZE> outSalt) {
    return generateIv(std::span<uint8_t, 16>(outSalt.data(), SALT_SIZE));
}

bool KeyDerivation::generateIv(std::span<uint8_t, 16> outIv) {
    size_t total = 0;
    while (total < outIv.size()) {
        const ssize_t count = ::getrandom(outIv.data() + total, outIv.size() - total, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            secureZero(outIv.data(), outIv.size());
            return false;
        }
        total += static_cast<size_t>(count);
    }
    return true;
}

// ============================================================================
// HmacContext Streaming Implementation
// ============================================================================

struct HmacContext::Impl {
    Sha256Context innerCtx;
    std::array<uint8_t, 64> opad{};
    bool initialized{false};

    Impl() = default;
    ~Impl() {
        reset();
    }

    void reset() noexcept {
        KeyDerivation::secureZero(opad.data(), sizeof(opad));
        innerCtx.reset();
        initialized = false;
    }
};

HmacContext::HmacContext() : m_impl(std::make_unique<Impl>()) {}
HmacContext::~HmacContext() = default;
HmacContext::HmacContext(HmacContext&&) noexcept = default;
HmacContext& HmacContext::operator=(HmacContext&&) noexcept = default;

void HmacContext::reset() noexcept {
    if (m_impl) {
        m_impl->reset();
    }
}

bool HmacContext::init(std::span<const uint8_t> key) {
    if (!m_impl) {
        m_impl = std::make_unique<Impl>();
    }
    m_impl->reset();

    std::array<uint8_t, 64> k_pad{};
    std::array<uint8_t, 64> ipad{};

    if (key.size() > 64) {
        std::array<uint8_t, 32> hashedKey{};
        internalSha256(key.data(), key.size(), hashedKey);
        std::memcpy(k_pad.data(), hashedKey.data(), 32);
        KeyDerivation::secureZero(hashedKey.data(), sizeof(hashedKey));
    } else {
        std::memcpy(k_pad.data(), key.data(), key.size());
    }

    for (size_t i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(k_pad[i] ^ 0x36);
        m_impl->opad[i] = static_cast<uint8_t>(k_pad[i] ^ 0x5c);
    }

    m_impl->innerCtx.reset();
    m_impl->innerCtx.update(ipad.data(), 64);

    KeyDerivation::secureZero(k_pad.data(), sizeof(k_pad));
    KeyDerivation::secureZero(ipad.data(), sizeof(ipad));

    m_impl->initialized = true;
    return true;
}

bool HmacContext::update(std::span<const uint8_t> data) {
    if (!m_impl || !m_impl->initialized) {
        return false;
    }
    if (!data.empty()) {
        m_impl->innerCtx.update(data.data(), data.size());
    }
    return true;
}

bool HmacContext::update(const void* data, size_t length) {
    if (!m_impl || !m_impl->initialized) {
        return false;
    }
    if (data && length > 0) {
        m_impl->innerCtx.update(static_cast<const uint8_t*>(data), length);
    }
    return true;
}

bool HmacContext::finalize(std::span<uint8_t, KeyDerivation::HMAC_SIZE> outHmac) {
    if (!m_impl || !m_impl->initialized) {
        return false;
    }

    std::array<uint8_t, 32> innerHash{};
    m_impl->innerCtx.finalize(innerHash);

    Sha256Context outerCtx;
    outerCtx.update(m_impl->opad.data(), 64);
    outerCtx.update(innerHash.data(), innerHash.size());
    outerCtx.finalize(outHmac);

    KeyDerivation::secureZero(innerHash.data(), sizeof(innerHash));
    m_impl->reset();
    return true;
}

bool HmacContext::verifyConstantTime(std::span<const uint8_t, KeyDerivation::HMAC_SIZE> expectedHmac) {
    std::array<uint8_t, KeyDerivation::HMAC_SIZE> computed{};
    if (!finalize(computed)) {
        return false;
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < KeyDerivation::HMAC_SIZE; ++i) {
        const uint8_t byteDiff = static_cast<uint8_t>(computed[i] ^ expectedHmac[i]);
        diff = static_cast<uint8_t>(diff | byteDiff);
    }

    KeyDerivation::secureZero(computed.data(), sizeof(computed));
    return diff == 0;
}

bool KeyDerivation::computeHmacSha256(std::span<const uint8_t> key,
                                     std::span<const uint8_t> data,
                                     std::span<uint8_t, HMAC_SIZE> outHmac) {
    return computeHmacSha256(key, std::span<const uint8_t>{}, data, outHmac);
}

bool KeyDerivation::computeHmacSha256(std::span<const uint8_t> key,
                                     std::span<const uint8_t> first,
                                     std::span<const uint8_t> second,
                                     std::span<uint8_t, HMAC_SIZE> outHmac) {
    HmacContext ctx;
    if (!ctx.init(key)) return false;
    if (!ctx.update(first)) return false;
    if (!ctx.update(second)) return false;
    return ctx.finalize(outHmac);
}

bool KeyDerivation::verifyHmacConstantTime(std::span<const uint8_t> key,
                                          std::span<const uint8_t> data,
                                          std::span<const uint8_t, HMAC_SIZE> expectedHmac) {
    return verifyHmacConstantTime(key, std::span<const uint8_t>{}, data, expectedHmac);
}

bool KeyDerivation::verifyHmacConstantTime(std::span<const uint8_t> key,
                                          std::span<const uint8_t> first,
                                          std::span<const uint8_t> second,
                                          std::span<const uint8_t, HMAC_SIZE> expectedHmac) {
    HmacContext ctx;
    if (!ctx.init(key)) return false;
    if (!ctx.update(first)) return false;
    if (!ctx.update(second)) return false;
    return ctx.verifyConstantTime(expectedHmac);
}

namespace {

bool computePbkdf2Block(std::span<const uint8_t> passBytes,
                        std::span<const uint8_t> salt,
                        uint32_t blockIndex,
                        uint32_t iterations,
                        std::span<uint8_t, 32> outBlock) {
    std::vector<uint8_t> saltPlusIndex;
    saltPlusIndex.reserve(salt.size() + 4);
    saltPlusIndex.insert(saltPlusIndex.end(), salt.begin(), salt.end());
    saltPlusIndex.push_back(static_cast<uint8_t>((blockIndex >> 24) & 0xFF));
    saltPlusIndex.push_back(static_cast<uint8_t>((blockIndex >> 16) & 0xFF));
    saltPlusIndex.push_back(static_cast<uint8_t>((blockIndex >> 8) & 0xFF));
    saltPlusIndex.push_back(static_cast<uint8_t>(blockIndex & 0xFF));

    std::array<uint8_t, 32> u_prev{};
    std::array<uint8_t, 32> u_curr{};
    std::array<uint8_t, 32> f_acc{};

    if (!KeyDerivation::computeHmacSha256(passBytes, saltPlusIndex, u_prev)) {
        return false;
    }
    std::memcpy(f_acc.data(), u_prev.data(), 32);

    for (uint32_t iter = 2; iter <= iterations; ++iter) {
        if (!KeyDerivation::computeHmacSha256(passBytes, u_prev, u_curr)) {
            KeyDerivation::secureZero(saltPlusIndex.data(), saltPlusIndex.size());
            KeyDerivation::secureZero(u_prev.data(), sizeof(u_prev));
            KeyDerivation::secureZero(u_curr.data(), sizeof(u_curr));
            KeyDerivation::secureZero(f_acc.data(), sizeof(f_acc));
            return false;
        }

        for (size_t b = 0; b < 32; ++b) {
            f_acc[b] ^= u_curr[b];
        }
        std::memcpy(u_prev.data(), u_curr.data(), 32);
    }

    std::memcpy(outBlock.data(), f_acc.data(), 32);

    KeyDerivation::secureZero(saltPlusIndex.data(), saltPlusIndex.size());
    KeyDerivation::secureZero(u_prev.data(), sizeof(u_prev));
    KeyDerivation::secureZero(u_curr.data(), sizeof(u_curr));
    KeyDerivation::secureZero(f_acc.data(), sizeof(f_acc));
    return true;
}

} // namespace

bool KeyDerivation::deriveKeyPbkdf2(std::string_view passphrase,
                                    std::span<const uint8_t> salt,
                                    std::span<uint8_t, KEY_SIZE> outKey,
                                    uint32_t iterations) {
    if (passphrase.empty() || salt.empty() || iterations == 0) {
        return false;
    }

    std::span<const uint8_t> passBytes(
        reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    // Single-block PBKDF2: Block 1 (T_1) -> 32 bytes
    return computePbkdf2Block(passBytes, salt, 1, iterations, outKey);
}

bool KeyDerivation::deriveDualKeysPbkdf2(std::string_view passphrase,
                                        std::span<const uint8_t> salt,
                                        std::span<uint8_t, KEY_SIZE> outEncKey,
                                        std::span<uint8_t, HMAC_SIZE> outMacKey,
                                        uint32_t iterations) {
    if (passphrase.empty() || salt.empty() || iterations == 0) {
        return false;
    }

    std::span<const uint8_t> passBytes(
        reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    // Block 1 (T_1) -> AES-256 Encryption Key
    if (!computePbkdf2Block(passBytes, salt, 1, iterations, outEncKey)) {
        return false;
    }

    // Block 2 (T_2) -> HMAC-SHA256 Authentication Key
    if (!computePbkdf2Block(passBytes, salt, 2, iterations, outMacKey)) {
        secureZero(outEncKey.data(), outEncKey.size());
        return false;
    }

    return true;
}

} // namespace kvault
