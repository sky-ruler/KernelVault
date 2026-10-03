/**
 * @file KeyDerivation.hpp
 * @brief High-assurance Key Derivation and Zero-Trust Memory Hygiene Service for kvault.
 *
 * Implements PBKDF2-HMAC-SHA256 (RFC 2898), cryptographic salt generation,
 * message authentication (HMAC-SHA256), and compiler-barrier memory wiping.
 */

#ifndef KEY_DERIVATION_HPP
#define KEY_DERIVATION_HPP

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <span>
#include <vector>
#include <memory>
#include <array>

namespace kvault {

class HmacContext;

/**
 * @class KeyDerivation
 * @brief Cryptographic key derivation and memory scrub utility.
 */
class KeyDerivation {
public:
    static constexpr size_t KEY_SIZE = 32;       /**< 256-bit AES key size */
    static constexpr size_t SALT_SIZE = 16;      /**< 128-bit salt size */
    static constexpr size_t HMAC_SIZE = 32;      /**< 256-bit HMAC size */
    static constexpr uint32_t DEFAULT_ITERATIONS = 100000; /**< Standard PBKDF2 iteration count */

    /**
     * @brief Derives a 256-bit key from a passphrase and salt using PBKDF2-HMAC-SHA256.
     * @param passphrase Plaintext user passphrase.
     * @param salt Cryptographic salt (minimum 16 bytes recommended).
     * @param outKey Output span of 32 bytes to store the derived key.
     * @param iterations PBKDF2 iteration rounds (defaults to 100,000).
     * @return True if derivation succeeded, false otherwise.
     */
    static bool deriveKeyPbkdf2(std::string_view passphrase,
                                std::span<const uint8_t> salt,
                                std::span<uint8_t, KEY_SIZE> outKey,
                                uint32_t iterations = DEFAULT_ITERATIONS);

    /**
     * @brief Derives dual distinct 256-bit keys for encryption and MAC from passphrase and salt.
     * Enforces cryptographic protocol hygiene (RFC 2898 multi-block PBKDF2).
     * @param passphrase Plaintext user passphrase.
     * @param salt Cryptographic salt.
     * @param outEncKey Output span of 32 bytes to store the derived AES-256 cipher key (Block 1).
     * @param outMacKey Output span of 32 bytes to store the derived HMAC-SHA256 auth key (Block 2).
     * @param iterations PBKDF2 iteration rounds (defaults to 100,000).
     * @return True if derivation succeeded, false otherwise.
     */
    static bool deriveDualKeysPbkdf2(std::string_view passphrase,
                                     std::span<const uint8_t> salt,
                                     std::span<uint8_t, KEY_SIZE> outEncKey,
                                     std::span<uint8_t, HMAC_SIZE> outMacKey,
                                     uint32_t iterations = DEFAULT_ITERATIONS);

    /**
     * @brief Generates cryptographically secure pseudo-random salt.
     * @param outSalt Output span to receive random bytes.
     * @return True on success, false if OS entropy source failed.
     */
    static bool generateSalt(std::span<uint8_t, SALT_SIZE> outSalt);

    /**
     * @brief Generates cryptographically secure pseudo-random initialization vector (IV).
     * @param outIv Output span of 16 bytes.
     * @return True on success, false otherwise.
     */
    static bool generateIv(std::span<uint8_t, 16> outIv);

    /**
     * @brief Computes HMAC-SHA256 over a binary payload.
     * @param key Authentication key.
     * @param data Payload data.
     * @param outHmac Output buffer of 32 bytes for the HMAC tag.
     * @return True on success, false otherwise.
     */
    static bool computeHmacSha256(std::span<const uint8_t> key,
                                 std::span<const uint8_t> data,
                                 std::span<uint8_t, HMAC_SIZE> outHmac);

    /**
     * @brief Computes HMAC-SHA256 over two concatenated spans without copying them.
     */
    static bool computeHmacSha256(std::span<const uint8_t> key,
                                 std::span<const uint8_t> first,
                                 std::span<const uint8_t> second,
                                 std::span<uint8_t, HMAC_SIZE> outHmac);

    /**
     * @brief Verifies HMAC-SHA256 in constant time to prevent timing side-channel attacks.
     * @param key Authentication key.
     * @param data Payload data.
     * @param expectedHmac Expected 32-byte HMAC tag.
     * @return True if tag matches, false otherwise.
     */
    static bool verifyHmacConstantTime(std::span<const uint8_t> key,
                                       std::span<const uint8_t> data,
                                       std::span<const uint8_t, HMAC_SIZE> expectedHmac);

    /**
     * @brief Verifies HMAC-SHA256 over two concatenated spans in constant time.
     */
    static bool verifyHmacConstantTime(std::span<const uint8_t> key,
                                       std::span<const uint8_t> first,
                                       std::span<const uint8_t> second,
                                       std::span<const uint8_t, HMAC_SIZE> expectedHmac);

    /**
     * @brief Securely scrubs memory buffer, preventing dead-store elimination by the compiler.
     * @param ptr Pointer to memory buffer.
     * @param length Number of bytes to scrub.
     */
    static void secureZero(void* ptr, size_t length) noexcept;

    /**
     * @brief RAII wrapper for auto-zeroing memory buffer upon destruction.
     */
    template <typename T>
    struct SecureBuffer {
        std::vector<T> data;

        explicit SecureBuffer(size_t size = 0, T val = T{}) : data(size, val) {}
        ~SecureBuffer() {
            if (!data.empty()) {
                secureZero(data.data(), data.size() * sizeof(T));
            }
        }

        SecureBuffer(const SecureBuffer&) = delete;
        SecureBuffer& operator=(const SecureBuffer&) = delete;
        SecureBuffer(SecureBuffer&&) noexcept = default;
        SecureBuffer& operator=(SecureBuffer&&) noexcept = default;

        T* data_ptr() noexcept { return data.data(); }
        const T* data_ptr() const noexcept { return data.data(); }
        size_t size() const noexcept { return data.size(); }
        T& operator[](size_t idx) { return data[idx]; }
        const T& operator[](size_t idx) const { return data[idx]; }
    };
};

/**
 * @class HmacContext
 * @brief Stateful streaming HMAC-SHA256 engine enabling O(1) bounded-RAM processing.
 */
class HmacContext {
public:
    HmacContext();
    ~HmacContext();

    HmacContext(const HmacContext&) = delete;
    HmacContext& operator=(const HmacContext&) = delete;
    HmacContext(HmacContext&&) noexcept;
    HmacContext& operator=(HmacContext&&) noexcept;

    /**
     * @brief Initializes the HMAC engine with an authentication key.
     * @param key Authentication key span.
     * @return True on success.
     */
    bool init(std::span<const uint8_t> key);

    /**
     * @brief Ingests an arbitrary chunk of data into the running HMAC calculation.
     * @param data Data span to ingest.
     * @return True on success.
     */
    bool update(std::span<const uint8_t> data);

    /**
     * @brief Ingests raw buffer into running HMAC calculation.
     * @param data Pointer to data bytes.
     * @param length Number of bytes.
     * @return True on success.
     */
    bool update(const void* data, size_t length);

    /**
     * @brief Finalizes the HMAC calculation, outputs the 32-byte tag, and resets the state.
     * @param outHmac Output buffer for 32-byte tag.
     * @return True on success.
     */
    bool finalize(std::span<uint8_t, KeyDerivation::HMAC_SIZE> outHmac);

    /**
     * @brief Finalizes and verifies against an expected HMAC tag in constant time.
     * @param expectedHmac Expected 32-byte authentication tag.
     * @return True if tag matches exactly, false otherwise.
     */
    bool verifyConstantTime(std::span<const uint8_t, KeyDerivation::HMAC_SIZE> expectedHmac);

    /**
     * @brief Resets the internal state and securely zeros any key-derived material.
     */
    void reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace kvault

#endif // KEY_DERIVATION_HPP
