/**
 * @file VaultManager.cpp
 * @brief Implementation of VaultManager orchestration and cryptographic streaming for kvault.
 */

#include "VaultManager.hpp"
#include "Logger.hpp"

#include <fstream>
#include <sstream>
#include <cstring>
#include <array>
#include <algorithm>
#include <limits>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <time.h>
#include <endian.h>

namespace kvault {

namespace {

bool isValidVaultFilename(std::string_view filename) {
    if (filename.empty() || filename == "." || filename == "..") {
        return false;
    }
    if (filename.find('/') != std::string_view::npos ||
        filename.find('\\') != std::string_view::npos ||
        filename.find("..") != std::string_view::npos ||
        filename.find('\0') != std::string_view::npos) {
        return false;
    }
    for (char c : filename) {
        if (static_cast<unsigned char>(c) < 32 || c == 127) {
            return false;
        }
    }
    return std::filesystem::path(filename).filename().string() == filename;
}

// ============================================================================
// Internal Standalone AES-256 Engine for User-Space Fallback / Mock Mode
// ============================================================================

class SoftwareAes256 {
public:
    [[maybe_unused]] static constexpr size_t BLOCK_SIZE = 16;
    [[maybe_unused]] static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t ROUND_KEYS_SIZE = 240; // (14 + 1) * 16

    static void expandKey(std::span<const uint8_t, 32> key, uint8_t* roundKeys) noexcept {
        static const uint8_t rcon[15] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x00, 0x00, 0x00, 0x00
        };

        std::memcpy(roundKeys, key.data(), 32);

        uint32_t temp = 0;
        size_t bytesGenerated = 32;
        size_t rconIter = 1;

        while (bytesGenerated < ROUND_KEYS_SIZE) {
            temp = (static_cast<uint32_t>(roundKeys[bytesGenerated - 4]) << 24) |
                   (static_cast<uint32_t>(roundKeys[bytesGenerated - 3]) << 16) |
                   (static_cast<uint32_t>(roundKeys[bytesGenerated - 2]) << 8)  |
                   (static_cast<uint32_t>(roundKeys[bytesGenerated - 1]));

            if (bytesGenerated % 32 == 0) {
                // RotWord & SubWord
                temp = (temp << 8) | (temp >> 24);
                temp = subWord(temp) ^ (static_cast<uint32_t>(rcon[rconIter++]) << 24);
            } else if (bytesGenerated % 32 == 16) {
                temp = subWord(temp);
            }

            uint32_t prev = (static_cast<uint32_t>(roundKeys[bytesGenerated - 32]) << 24) |
                            (static_cast<uint32_t>(roundKeys[bytesGenerated - 31]) << 16) |
                            (static_cast<uint32_t>(roundKeys[bytesGenerated - 30]) << 8)  |
                            (static_cast<uint32_t>(roundKeys[bytesGenerated - 29]));

            uint32_t result = prev ^ temp;
            roundKeys[bytesGenerated + 0] = static_cast<uint8_t>((result >> 24) & 0xFF);
            roundKeys[bytesGenerated + 1] = static_cast<uint8_t>((result >> 16) & 0xFF);
            roundKeys[bytesGenerated + 2] = static_cast<uint8_t>((result >> 8) & 0xFF);
            roundKeys[bytesGenerated + 3] = static_cast<uint8_t>(result & 0xFF);

            bytesGenerated += 4;
        }
    }

    static void encryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* roundKeys) noexcept {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        addRoundKey(state, roundKeys);

        for (int round = 1; round < 14; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys + round * 16);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys + 14 * 16);

        std::memcpy(out, state, 16);
        KeyDerivation::secureZero(state, sizeof(state));
    }

    static void decryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* roundKeys) noexcept {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        addRoundKey(state, roundKeys + 14 * 16);

        for (int round = 13; round >= 1; --round) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys + round * 16);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys);

        std::memcpy(out, state, 16);
        KeyDerivation::secureZero(state, sizeof(state));
    }

private:
    static const uint8_t sbox[256];
    static const uint8_t rsbox[256];

    static uint32_t subWord(uint32_t word) noexcept {
        return (static_cast<uint32_t>(sbox[(word >> 24) & 0xFF]) << 24) |
               (static_cast<uint32_t>(sbox[(word >> 16) & 0xFF]) << 16) |
               (static_cast<uint32_t>(sbox[(word >> 8) & 0xFF]) << 8)   |
               (static_cast<uint32_t>(sbox[word & 0xFF]));
    }

    static void addRoundKey(uint8_t* state, const uint8_t* key) noexcept {
        for (int i = 0; i < 16; ++i) state[i] ^= key[i];
    }

    static void subBytes(uint8_t* state) noexcept {
        for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
    }

    static void invSubBytes(uint8_t* state) noexcept {
        for (int i = 0; i < 16; ++i) state[i] = rsbox[state[i]];
    }

    static void shiftRows(uint8_t* state) noexcept {
        uint8_t temp[16];
        temp[0] = state[0];   temp[1] = state[5];   temp[2] = state[10];  temp[3] = state[15];
        temp[4] = state[4];   temp[5] = state[9];   temp[6] = state[14];  temp[7] = state[3];
        temp[8] = state[8];   temp[9] = state[13];  temp[10] = state[2];  temp[11] = state[7];
        temp[12] = state[12]; temp[13] = state[1];  temp[14] = state[6];  temp[15] = state[11];
        std::memcpy(state, temp, 16);
    }

    static void invShiftRows(uint8_t* state) noexcept {
        uint8_t temp[16];
        temp[0] = state[0];   temp[1] = state[13];  temp[2] = state[10];  temp[3] = state[7];
        temp[4] = state[4];   temp[5] = state[1];   temp[6] = state[14];  temp[7] = state[11];
        temp[8] = state[8];   temp[9] = state[5];   temp[10] = state[2];  temp[11] = state[15];
        temp[12] = state[12]; temp[13] = state[9];  temp[14] = state[6];  temp[15] = state[3];
        std::memcpy(state, temp, 16);
    }

    static uint8_t xtime(uint8_t x) noexcept {
        return static_cast<uint8_t>((static_cast<uint32_t>(x) << 1) ^ (((static_cast<uint32_t>(x) >> 7) & 1U) * 0x1bU));
    }

    static uint8_t multiply(uint8_t x, uint8_t y) noexcept {
        return static_cast<uint8_t>(
            ((static_cast<uint32_t>(y) & 1U) * static_cast<uint32_t>(x)) ^
            (((static_cast<uint32_t>(y) >> 1) & 1U) * static_cast<uint32_t>(xtime(x))) ^
            (((static_cast<uint32_t>(y) >> 2) & 1U) * static_cast<uint32_t>(xtime(xtime(x)))) ^
            (((static_cast<uint32_t>(y) >> 3) & 1U) * static_cast<uint32_t>(xtime(xtime(xtime(x))))) ^
            (((static_cast<uint32_t>(y) >> 4) & 1U) * static_cast<uint32_t>(xtime(xtime(xtime(xtime(x)))))));
    }

    static void mixColumns(uint8_t* state) noexcept {
        for (int i = 0; i < 4; ++i) {
            uint8_t* c = state + i * 4;
            uint8_t a = c[0], b = c[1], d = c[2], e = c[3];
            c[0] = static_cast<uint8_t>(xtime(a) ^ (b ^ xtime(b)) ^ d ^ e);
            c[1] = static_cast<uint8_t>(a ^ xtime(b) ^ (d ^ xtime(d)) ^ e);
            c[2] = static_cast<uint8_t>(a ^ b ^ xtime(d) ^ (e ^ xtime(e)));
            c[3] = static_cast<uint8_t>((a ^ xtime(a)) ^ b ^ d ^ xtime(e));
        }
    }

    static void invMixColumns(uint8_t* state) noexcept {
        for (int i = 0; i < 4; ++i) {
            uint8_t* c = state + i * 4;
            uint8_t a = c[0], b = c[1], d = c[2], e = c[3];
            c[0] = static_cast<uint8_t>(multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(d, 0x0d) ^ multiply(e, 0x09));
            c[1] = static_cast<uint8_t>(multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(d, 0x0b) ^ multiply(e, 0x0d));
            c[2] = static_cast<uint8_t>(multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(d, 0x0e) ^ multiply(e, 0x0b));
            c[3] = static_cast<uint8_t>(multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(d, 0x09) ^ multiply(e, 0x0e));
        }
    }
};

const uint8_t SoftwareAes256::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t SoftwareAes256::rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

} // namespace

// ============================================================================
// VaultManager Implementation
// ============================================================================

VaultManager::VaultManager(std::filesystem::path vaultPath)
    : m_vaultPath(std::move(vaultPath)) {
    m_recordsPath = m_vaultPath / "records";
    m_locksPath = m_vaultPath / "locks";
    m_metaPath = m_vaultPath / "vault.meta";
}

VaultManager::~VaultManager() noexcept = default;

bool VaultManager::initializeVault() {
    std::error_code ec;

    if (std::filesystem::exists(m_metaPath)) {
        Logger::error("Vault already initialized at: " + m_vaultPath.string());
        return false;
    }

    // Create directories
    std::filesystem::create_directories(m_recordsPath, ec);
    std::filesystem::create_directories(m_locksPath, ec);

    if (ec) {
        Logger::error("Failed to create vault directories: " + ec.message());
        return false;
    }

    // Generate Master Salt
    std::array<uint8_t, 16> masterSalt{};
    if (!KeyDerivation::generateSalt(masterSalt)) {
        Logger::error("Operating system entropy source failed while initializing the vault");
        return false;
    }

    // Write vault.meta manifest
    AtomicFileWriter metaWriter(m_metaPath, false);
    if (!metaWriter.open()) {
        Logger::error("Failed to open vault metadata file for writing.");
        return false;
    }

    std::string metaContent = "KVLT01\n";
    metaContent += "version=1\n";
    metaContent += "kdf=PBKDF2-HMAC-SHA256\n";
    metaContent += "rounds=100000\n";
    metaContent += "salt=";
    for (uint8_t b : masterSalt) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        metaContent += buf;
    }
    metaContent += "\n";

    std::span<const uint8_t> spanData(reinterpret_cast<const uint8_t*>(metaContent.data()), metaContent.size());
    if (!metaWriter.write(spanData) || !metaWriter.commit()) {
        Logger::error("Failed to atomically commit vault.meta");
        return false;
    }

    Logger::info("Initialized secure vault at: " + m_vaultPath.string());
    return true;
}

UniqueFd VaultManager::openKernelDevice() {
    int fd = ::open("/dev/kvault", O_RDWR);
    if (fd >= 0) {
        Logger::kernel("Opened Linux driver device /dev/kvault");
        return UniqueFd(fd);
    }
    return UniqueFd(-1);
}

bool VaultManager::configureKernelSession(int devFd,
                                         std::span<const uint8_t, 32> key,
                                         std::span<const uint8_t, 16> iv,
                                         int mode) {
    if (devFd < 0) return false;

    // 1. Set mode
    if (::ioctl(devFd, KVAULT_IOCTL_SET_MODE, &mode) != 0) {
        return false;
    }

    // 2. Set key
    struct kvault_key_param key_param{};
    std::memcpy(key_param.key, key.data(), 32);
    key_param.key_len = 32;
    if (::ioctl(devFd, KVAULT_IOCTL_SET_KEY, &key_param) != 0) {
        KeyDerivation::secureZero(&key_param, sizeof(key_param));
        return false;
    }
    KeyDerivation::secureZero(&key_param, sizeof(key_param));

    // 3. Set IV
    struct kvault_iv_param iv_param{};
    std::memcpy(iv_param.iv, iv.data(), 16);
    iv_param.iv_len = 16;
    if (::ioctl(devFd, KVAULT_IOCTL_SET_IV, &iv_param) != 0) {
        return false;
    }

    return true;
}

void VaultManager::flushKernelSession(int devFd) {
    if (devFd >= 0) {
        ::ioctl(devFd, KVAULT_IOCTL_FLUSH_KEY);
        Logger::kernel("Dispatched KVAULT_IOCTL_FLUSH_KEY to wipe in-kernel key memory");
    }
}

bool VaultManager::transformBuffer(int devFd,
                                  std::span<const uint8_t> input,
                                  std::vector<uint8_t>& output,
                                  std::span<const uint8_t, 32> key,
                                  std::span<uint8_t, 16> iv,
                                  bool encrypt) {
    if (input.empty()) {
        output.clear();
        return true;
    }

    if (devFd >= 0) {
        // Kernel acceleration path via IOCTL transform
        output.resize(input.size());
        struct kvault_transform_param trans{};
        trans.src = input.data();
        trans.dst = output.data();
        trans.length = static_cast<uint32_t>(input.size());
        trans.mode = encrypt ? KVAULT_MODE_ENCRYPT : KVAULT_MODE_DECRYPT;

        if (::ioctl(devFd, KVAULT_IOCTL_TRANSFORM, &trans) == 0) {
            if (encrypt) {
                std::memcpy(iv.data(), output.data() + output.size() - 16, 16);
            } else {
                std::memcpy(iv.data(), input.data() + input.size() - 16, 16);
            }
            return true;
        }
        Logger::warn("Kernel IOCTL transform failed, falling back to software cipher");
    }

    // Fallback: Software AES-256-CBC engine
    output.resize(input.size());
    uint8_t roundKeys[SoftwareAes256::ROUND_KEYS_SIZE];
    SoftwareAes256::expandKey(key, roundKeys);

    uint8_t currentIv[16];
    std::memcpy(currentIv, iv.data(), 16);

    for (size_t offset = 0; offset < input.size(); offset += 16) {
        const uint8_t* inBlock = input.data() + offset;
        uint8_t* outBlock = output.data() + offset;

        if (encrypt) {
            uint8_t xored[16];
            for (int i = 0; i < 16; ++i) {
                xored[i] = inBlock[i] ^ currentIv[i];
            }
            SoftwareAes256::encryptBlock(xored, outBlock, roundKeys);
            std::memcpy(currentIv, outBlock, 16);
            KeyDerivation::secureZero(xored, sizeof(xored));
        } else {
            uint8_t decrypted[16];
            SoftwareAes256::decryptBlock(inBlock, decrypted, roundKeys);
            for (int i = 0; i < 16; ++i) {
                outBlock[i] = decrypted[i] ^ currentIv[i];
            }
            std::memcpy(currentIv, inBlock, 16);
            KeyDerivation::secureZero(decrypted, sizeof(decrypted));
        }
    }

    // Update session IV
    std::memcpy(iv.data(), currentIv, 16);
    KeyDerivation::secureZero(roundKeys, sizeof(roundKeys));
    KeyDerivation::secureZero(currentIv, sizeof(currentIv));

    return true;
}

std::filesystem::path VaultManager::getLockFilePath(const std::string& filename) const {
    std::filesystem::path leaf = std::filesystem::path(filename).filename();
    std::string safeName = leaf.string();
    if (!isValidVaultFilename(safeName) || safeName.find("..") != std::string::npos || safeName.find('/') != std::string::npos) {
        safeName = "invalid";
    }
    return (m_locksPath / (safeName + ".lock")).lexically_normal();
}

std::filesystem::path VaultManager::getRecordFilePath(const std::string& filename) const {
    std::filesystem::path leaf = std::filesystem::path(filename).filename();
    std::string safeName = leaf.string();
    if (!isValidVaultFilename(safeName) || safeName.find("..") != std::string::npos || safeName.find('/') != std::string::npos) {
        safeName = "invalid";
    }
    return (m_recordsPath / (safeName + ".enc")).lexically_normal();
}

bool VaultManager::encryptFile(const std::filesystem::path& srcFile, std::string_view passphrase) {
    std::error_code ec;
    if (std::filesystem::is_symlink(srcFile, ec)) {
        Logger::error("Source file cannot be a symbolic link (symlink defense): " + srcFile.string());
        return false;
    }
    if (!std::filesystem::exists(srcFile, ec) || !std::filesystem::is_regular_file(srcFile, ec)) {
        Logger::error("Source file does not exist or is not a regular file: " + srcFile.string());
        return false;
    }

    const std::string filename = srcFile.filename().string();
    if (!isValidVaultFilename(filename) || filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        Logger::error("Invalid or prohibited filename: " + filename);
        return false;
    }

    const auto lockPath = getLockFilePath(filename);
    const auto destRecordPath = getRecordFilePath(filename);
    if (lockPath.string().find("..") != std::string::npos || destRecordPath.string().find("..") != std::string::npos) {
        Logger::error("Path traversal detected in vault paths");
        return false;
    }

    // 1. Acquire POSIX advisory write lock (exclusive)
    int lockFdRaw = ::open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

    UniqueFd lockFd(lockFdRaw);
    if (!lockFd.valid()) {
        Logger::error("Failed to open lock file: " + lockPath.string());
        return false;
    }

    FileLock fileLock(lockFd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
    if (!fileLock.isLocked()) {
        Logger::error("Cannot acquire exclusive lock on: " + filename + " (file is currently in use)");
        return false;
    }

    // 2. Generate Salt & IV
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 16> iv{};
    if (!KeyDerivation::generateSalt(salt) || !KeyDerivation::generateIv(iv)) {
        Logger::error("Operating system entropy source failed; encryption was not started");
        KeyDerivation::secureZero(salt.data(), salt.size());
        KeyDerivation::secureZero(iv.data(), iv.size());
        return false;
    }

    // 3. Derive distinct 256-bit AES Key and 256-bit HMAC Key (RFC 2898 multi-block PBKDF2)
    PinnedMemory<32> encKey;
    PinnedMemory<32> macKey;
    if (!KeyDerivation::deriveDualKeysPbkdf2(passphrase, salt, encKey.span(), macKey.span())) {
        Logger::error("Dual-key derivation failed");
        return false;
    }

    // 4. Check for Kernel Device Accelerator
    UniqueFd devFd = openKernelDevice();
    bool useKernel = devFd.valid();
    if (useKernel) {
        if (!configureKernelSession(devFd.get(), encKey.span(), iv, KVAULT_MODE_ENCRYPT)) {
            Logger::warn("Failed to configure kernel crypto session. Reverting to software engine.");
            devFd.reset(-1);
            useKernel = false;
        }
    } else {
        Logger::info("Operating in user-space crypto engine mode (kernel module not active)");
    }

    // 5. Open Input File
    std::ifstream inFile(srcFile, std::ios::binary);
    if (!inFile) {
        Logger::error("Cannot open source file for reading: " + srcFile.string());
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    const uint64_t originalFileSize = std::filesystem::file_size(srcFile);
    const uint64_t paddingSize = 16 - (originalFileSize % 16);
    const uint64_t totalCipherBytes = (originalFileSize == 0) ? 0 : (originalFileSize + paddingSize);

    // 6. Prepare AtomicFileWriter for Vault Record
    AtomicFileWriter writer(destRecordPath, true);
    if (!writer.open()) {
        Logger::error("Failed to open atomic record destination: " + destRecordPath.string());
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    struct stat srcStat{};
    uint32_t posixMode = 0600;
    uint32_t mtimeEpoch = 0;
    if (::stat(srcFile.c_str(), &srcStat) == 0) {
        posixMode = static_cast<uint32_t>(srcStat.st_mode & 07777);
        mtimeEpoch = static_cast<uint32_t>(srcStat.st_mtime);
    }

    // Reserve 96 bytes for VaultHeader (written at commit) in canonical Little-Endian wire format
    VaultHeader header{};
    header.magic = htole32(VAULT_MAGIC);
    header.version = htole32(VAULT_VERSION);
    std::memcpy(header.salt, salt.data(), 16);
    std::memcpy(header.iv, iv.data(), 16);
    header.original_size = htole64(originalFileSize);
    header.payload_size = htole64(totalCipherBytes);
    header.posix_mode = htole32(posixMode);
    header.mtime_epoch = htole32(mtimeEpoch);

    std::vector<uint8_t> headerPlaceholder(sizeof(VaultHeader), 0);
    if (!writer.write(headerPlaceholder)) {
        Logger::error("Failed to reserve space for the vault record header");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    // 7. Initialize streaming HMAC authentication engine
    HmacContext hmacCtx;
    if (!hmacCtx.init(macKey.span())) {
        Logger::error("Failed to initialize HMAC context for streaming authentication");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    // Ingest the header (with empty hmac tag) into the running HMAC calculation
    if (!hmacCtx.update(&header, sizeof(header))) {
        Logger::error("Failed to ingest header into HMAC context");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    // 8. Stream and Encrypt File in Bounded Chunks (O(1) RAM)
    std::vector<uint8_t> inChunk(CHUNK_SIZE);
    std::vector<uint8_t> encryptedChunk;
    uint64_t actualCipherBytes = 0;

    std::array<uint8_t, 16> runningIv;
    std::memcpy(runningIv.data(), iv.data(), 16);

    while (inFile) {
        inFile.read(reinterpret_cast<char*>(inChunk.data()), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead <= 0) break;

        bool isEof = inFile.peek() == EOF;
        size_t chunkBytes = static_cast<size_t>(bytesRead);

        std::vector<uint8_t> toEncrypt;
        const auto chunkEnd = inChunk.begin() +
                              static_cast<std::vector<uint8_t>::difference_type>(chunkBytes);
        toEncrypt.insert(toEncrypt.end(), inChunk.begin(), chunkEnd);

        if (isEof) {
            size_t padLen = 16 - (chunkBytes % 16);
            for (size_t p = 0; p < padLen; ++p) {
                toEncrypt.push_back(static_cast<uint8_t>(padLen));
            }
        }

        if (!transformBuffer(devFd.get(), toEncrypt, encryptedChunk, encKey.span(), runningIv, true)) {
            Logger::error("Transform error during chunk encryption");
            writer.abort();
            if (useKernel) flushKernelSession(devFd.get());
            return false;
        }

        if (!writer.write(encryptedChunk)) {
            Logger::error("Failed to write encrypted data to the temporary vault record");
            writer.abort();
            if (useKernel) flushKernelSession(devFd.get());
            return false;
        }

        if (!hmacCtx.update(encryptedChunk)) {
            Logger::error("Failed to update streaming HMAC with ciphertext chunk");
            writer.abort();
            if (useKernel) flushKernelSession(devFd.get());
            return false;
        }

        actualCipherBytes += encryptedChunk.size();
    }

    if (inFile.bad() || actualCipherBytes != totalCipherBytes) {
        Logger::error("Input file read failed or size mismatch during encryption");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    // 9. Finalize HMAC tag
    std::array<uint8_t, 32> computedHmac{};
    if (!hmacCtx.finalize(computedHmac)) {
        Logger::error("Failed to finalize HMAC authentication tag");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }
    std::memcpy(header.hmac, computedHmac.data(), 32);
    KeyDerivation::secureZero(computedHmac.data(), computedHmac.size());

    // 10. Commit Atomic Write: rewrite header and flush
    std::fstream tmpStream(writer.getTempPath(), std::ios::in | std::ios::out | std::ios::binary);
    if (!tmpStream) {
        writer.abort();
        Logger::error("Failed to write authenticated header to temp vault file");
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }
    tmpStream.seekp(0);
    tmpStream.write(reinterpret_cast<const char*>(&header), sizeof(header));
    tmpStream.flush();
    tmpStream.close();

    if (!writer.commit()) {
        Logger::error("Atomic commit failed for encrypted vault record");
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    // 11. Memory Hygiene
    if (useKernel) {
        flushKernelSession(devFd.get());
    }
    KeyDerivation::secureZero(&header, sizeof(header));

    Logger::info("Successfully stored and encrypted into vault: " + filename +
                 " (" + std::to_string(originalFileSize) + " bytes -> " +
                 std::to_string(totalCipherBytes + sizeof(VaultHeader)) + " bytes on disk)");
    return true;
}

bool VaultManager::decryptFile(const std::string& filename,
                              const std::filesystem::path& destFile,
                              std::string_view passphrase) {
    if (!isValidVaultFilename(filename) || filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        Logger::error("Invalid or prohibited vault filename: " + filename);
        return false;
    }

    auto cleanDest = destFile.lexically_normal();
    if (cleanDest.string().find("..") != std::string::npos) {
        Logger::error("Path traversal detected in destination path: " + destFile.string());
        return false;
    }

    std::error_code ec;
    if (std::filesystem::exists(cleanDest, ec) && std::filesystem::is_symlink(cleanDest, ec)) {
        Logger::error("Destination cannot be an existing symbolic link (symlink defense): " + cleanDest.string());
        return false;
    }
    if (std::filesystem::is_directory(cleanDest, ec)) {
        Logger::error("Destination cannot be a directory: " + cleanDest.string());
        return false;
    }

    const auto lockPath = getLockFilePath(filename);
    const auto srcRecordPath = getRecordFilePath(filename);
    if (lockPath.string().find("..") != std::string::npos || srcRecordPath.string().find("..") != std::string::npos) {
        Logger::error("Path traversal detected in vault paths");
        return false;
    }

    if (!std::filesystem::exists(srcRecordPath, ec)) {
        Logger::error("Encrypted record not found in vault: " + filename);
        return false;
    }

    // 1. Acquire POSIX advisory read lock (shared)
    int lockFdRaw = ::open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    UniqueFd lockFd(lockFdRaw);
    if (!lockFd.valid()) {
        Logger::error("Failed to open lock file: " + lockPath.string());
        return false;
    }

    FileLock fileLock(lockFd.get(), FileLock::LockType::Shared, FileLock::LockMode::Blocking);
    if (!fileLock.isLocked()) {
        Logger::error("Cannot acquire shared lock on: " + filename + " (file is currently in use)");
        return false;
    }

    // 2. Read VaultHeader
    std::ifstream recordFile(srcRecordPath, std::ios::binary);
    if (!recordFile) {
        Logger::error("Cannot open vault record for reading: " + srcRecordPath.string());
        return false;
    }

    VaultHeader rawHeader{};
    recordFile.read(reinterpret_cast<char*>(&rawHeader), sizeof(rawHeader));
    if (recordFile.gcount() != sizeof(rawHeader)) {
        Logger::error("Corrupted vault record: Incomplete header");
        return false;
    }

    // Decode Little-Endian wire format fields to host values
    const uint32_t magic = le32toh(rawHeader.magic);
    const uint32_t version = le32toh(rawHeader.version);
    const uint64_t original_size = le64toh(rawHeader.original_size);
    const uint64_t payload_size = le64toh(rawHeader.payload_size);

    const bool supportedMagic = magic == VAULT_MAGIC ||
        (magic == LEGACY_MAGIC && version == LEGACY_VAULT_VERSION);
    const bool supportedVersion = version == VAULT_VERSION ||
        version == VAULT_VERSION_V2 ||
        version == LEGACY_VAULT_VERSION;
    if (!supportedMagic || !supportedVersion) {
        Logger::error("Invalid vault file magic or incompatible version.");
        return false;
    }

    const uint64_t paddingSize = 16 - (original_size % 16);
    const bool payloadLengthOverflow = original_size != 0 &&
        original_size > std::numeric_limits<uint64_t>::max() - paddingSize;
    const uint64_t expectedPayloadSize = original_size == 0
        ? 0
        : (payloadLengthOverflow ? 0 : original_size + paddingSize);
    std::error_code fileSizeError;
    const uintmax_t recordFileSize = std::filesystem::file_size(srcRecordPath, fileSizeError);
    const bool recordLengthOverflow = payload_size >
        std::numeric_limits<uintmax_t>::max() - sizeof(VaultHeader);
    const uintmax_t expectedRecordSize = recordLengthOverflow
        ? 0
        : sizeof(VaultHeader) + static_cast<uintmax_t>(payload_size);
    if (fileSizeError || payloadLengthOverflow || recordLengthOverflow ||
        payload_size != expectedPayloadSize ||
        original_size > payload_size || recordFileSize != expectedRecordSize ||
        payload_size > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
        payload_size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        Logger::error("Invalid vault record lengths or trailing data");
        return false;
    }

    // 3. Derive Keys (dual keys for V3, single key for legacy V1/V2)
    std::span<const uint8_t, 16> saltSpan(rawHeader.salt, 16);
    PinnedMemory<32> encKey;
    PinnedMemory<32> macKey;

    if (version >= VAULT_VERSION) {
        if (!KeyDerivation::deriveDualKeysPbkdf2(passphrase, saltSpan, encKey.span(), macKey.span())) {
            Logger::error("Key derivation failed during decryption");
            return false;
        }
    } else {
        if (!KeyDerivation::deriveKeyPbkdf2(passphrase, saltSpan, encKey.span())) {
            Logger::error("Key derivation failed during decryption");
            return false;
        }
        std::memcpy(macKey.data(), encKey.data(), 32);
    }

    // 4. PASS 1: Constant-Memory Streaming Authentication Check
    std::array<uint8_t, 32> expectedHmac{};
    std::memcpy(expectedHmac.data(), rawHeader.hmac, 32);

    HmacContext hmacCtx;
    if (!hmacCtx.init(macKey.span())) {
        Logger::error("Failed to initialize streaming HMAC verification context");
        return false;
    }

    if (version != LEGACY_VAULT_VERSION) {
        VaultHeader authenticatedHeader = rawHeader;
        KeyDerivation::secureZero(authenticatedHeader.hmac, sizeof(authenticatedHeader.hmac));
        if (!hmacCtx.update(&authenticatedHeader, sizeof(authenticatedHeader))) {
            Logger::error("Failed to update HMAC with authenticated header");
            return false;
        }
        KeyDerivation::secureZero(&authenticatedHeader, sizeof(authenticatedHeader));
    }

    std::vector<uint8_t> streamChunk(CHUNK_SIZE);
    uint64_t bytesRemaining = payload_size;
    while (bytesRemaining > 0) {
        const size_t toRead = static_cast<size_t>(
            std::min(static_cast<uint64_t>(CHUNK_SIZE), bytesRemaining));
        recordFile.read(reinterpret_cast<char*>(streamChunk.data()), static_cast<std::streamsize>(toRead));
        if (static_cast<size_t>(recordFile.gcount()) != toRead) {
            Logger::error("Corrupted vault record: Incomplete payload data during verification");
            return false;
        }
        if (!hmacCtx.update(streamChunk.data(), toRead)) {
            Logger::error("Streaming HMAC update failed");
            return false;
        }
        bytesRemaining -= toRead;
    }

    if (!hmacCtx.verifyConstantTime(expectedHmac)) {
        Logger::error("Cryptographic authentication failed: Incorrect passphrase or tampered ciphertext.");
        return false;
    }

    // 5. PASS 2: Constant-Memory Streaming Decryption to Destination File
    // Rewind file to start of payload
    recordFile.clear();
    recordFile.seekg(sizeof(VaultHeader), std::ios::beg);
    if (!recordFile) {
        Logger::error("Failed to seek to payload offset in vault record");
        return false;
    }

    UniqueFd devFd = openKernelDevice();
    bool useKernel = devFd.valid();
    std::array<uint8_t, 16> iv;
    std::memcpy(iv.data(), rawHeader.iv, 16);

    if (useKernel) {
        if (!configureKernelSession(devFd.get(), encKey.span(), iv, KVAULT_MODE_DECRYPT)) {
            devFd.reset(-1);
            useKernel = false;
        }
    }

    AtomicFileWriter writer(destFile, true);
    if (!writer.open()) {
        Logger::error("Failed to open destination file for atomic writing: " + destFile.string());
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    std::vector<uint8_t> decryptedChunk;
    bytesRemaining = payload_size;
    uint64_t totalDecryptedWritten = 0;

    while (bytesRemaining > 0) {
        const size_t toRead = static_cast<size_t>(
            std::min(static_cast<uint64_t>(CHUNK_SIZE), bytesRemaining));
        recordFile.read(reinterpret_cast<char*>(streamChunk.data()), static_cast<std::streamsize>(toRead));
        if (static_cast<size_t>(recordFile.gcount()) != toRead) {
            Logger::error("Corrupted vault record: Read failure during decryption stream");
            writer.abort();
            if (useKernel) flushKernelSession(devFd.get());
            return false;
        }

        std::span<const uint8_t> cipherSpan(streamChunk.data(), toRead);
        if (!transformBuffer(devFd.get(), cipherSpan, decryptedChunk, encKey.span(), iv, false)) {
            Logger::error("Decryption failed during chunk transform");
            writer.abort();
            if (useKernel) flushKernelSession(devFd.get());
            return false;
        }

        bytesRemaining -= toRead;
        const bool isLastChunk = (bytesRemaining == 0);

        if (isLastChunk && original_size > 0) {
            // Validate PKCS#7 padding on final block
            if (decryptedChunk.empty() || (decryptedChunk.size() % 16 != 0)) {
                Logger::error("Corrupted plaintext chunk alignment");
                writer.abort();
                if (useKernel) flushKernelSession(devFd.get());
                return false;
            }

            const uint8_t padLen = decryptedChunk.back();
            if (padLen == 0 || padLen > 16 || padLen > decryptedChunk.size()) {
                Logger::error("Invalid PKCS#7 padding detected in decrypted stream");
                writer.abort();
                if (useKernel) flushKernelSession(devFd.get());
                return false;
            }

            for (size_t p = 0; p < padLen; ++p) {
                if (decryptedChunk[decryptedChunk.size() - 1 - p] != padLen) {
                    Logger::error("Corrupted PKCS#7 padding sequence");
                    writer.abort();
                    if (useKernel) flushKernelSession(devFd.get());
                    return false;
                }
            }

            decryptedChunk.resize(decryptedChunk.size() - padLen);
        }

        if (!decryptedChunk.empty()) {
            if (!writer.write(decryptedChunk)) {
                Logger::error("Failed writing decrypted stream to atomic temp file");
                writer.abort();
                if (useKernel) flushKernelSession(devFd.get());
                return false;
            }
            totalDecryptedWritten += decryptedChunk.size();
        }

        KeyDerivation::secureZero(decryptedChunk.data(), decryptedChunk.size());
    }

    if (totalDecryptedWritten != original_size) {
        Logger::error("Recovered plaintext size does not match header original_size");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    if (!writer.commit()) {
        Logger::error("Failed to atomically commit recovered file: " + destFile.string());
        if (useKernel) flushKernelSession(devFd.get());
        return false;
    }

    // Restore POSIX permissions and timestamps if recorded in header (non-zero)
    const uint32_t restoredMode = le32toh(rawHeader.posix_mode);
    const uint32_t restoredMtime = le32toh(rawHeader.mtime_epoch);

    if (restoredMode != 0) {
        ::chmod(destFile.c_str(), static_cast<mode_t>(restoredMode & 07777));
    }

    if (restoredMtime != 0) {
        struct timespec times[2];
        times[0].tv_sec = static_cast<time_t>(restoredMtime); // atime
        times[0].tv_nsec = 0;
        times[1].tv_sec = static_cast<time_t>(restoredMtime); // mtime
        times[1].tv_nsec = 0;
        ::utimensat(AT_FDCWD, destFile.c_str(), times, 0);
    }

    // 6. Memory & Hardware Hygiene
    if (useKernel) {
        flushKernelSession(devFd.get());
    }
    KeyDerivation::secureZero(streamChunk.data(), streamChunk.size());
    KeyDerivation::secureZero(&rawHeader, sizeof(rawHeader));

    Logger::info("Successfully decrypted vault record into: " + destFile.string() +
                 " (" + std::to_string(totalDecryptedWritten) + " bytes recovered)");
    return true;
}

std::vector<VaultRecordInfo> VaultManager::listRecords() {
    std::vector<VaultRecordInfo> records;
    std::error_code ec;
    if (!std::filesystem::exists(m_recordsPath, ec)) {
        return records;
    }

    for (const auto& entry : std::filesystem::directory_iterator(m_recordsPath, ec)) {
        if (!entry.is_regular_file(ec) || entry.path().extension() != ".enc") {
            continue;
        }

        std::string filename = entry.path().stem().string();
        VaultRecordInfo info;
        info.filename = filename;

        std::ifstream file(entry.path(), std::ios::binary);
        if (file) {
            VaultHeader header{};
            file.read(reinterpret_cast<char*>(&header), sizeof(header));
            if (file.gcount() == sizeof(header)) {
                info.version = le32toh(header.version);
                info.original_size = le64toh(header.original_size);
                info.payload_size = le64toh(header.payload_size);
                info.posix_mode = le32toh(header.posix_mode);
                info.mtime_epoch = le32toh(header.mtime_epoch);
            }
        }

        const auto lockPath = getLockFilePath(filename);
        if (lockPath.string().find("..") == std::string::npos && std::filesystem::exists(lockPath, ec)) {
            int fd = ::open(lockPath.c_str(), O_RDWR);
            if (fd >= 0) {
                UniqueFd probeLock(fd);
                FileLock testLock(probeLock.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
                info.is_locked = !testLock.isLocked();
            }
        }

        records.push_back(std::move(info));
    }

    std::sort(records.begin(), records.end(), [](const VaultRecordInfo& a, const VaultRecordInfo& b) {
        return a.filename < b.filename;
    });

    return records;
}

bool VaultManager::deleteRecord(const std::string& filename) {
    if (!isValidVaultFilename(filename) || filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        Logger::error("Invalid or prohibited vault filename: " + filename);
        return false;
    }

    const auto lockPath = getLockFilePath(filename);
    const auto recordPath = getRecordFilePath(filename);
    if (lockPath.string().find("..") != std::string::npos || recordPath.string().find("..") != std::string::npos) {
        Logger::error("Path traversal detected in vault paths");
        return false;
    }

    std::error_code ec;
    if (!std::filesystem::exists(recordPath, ec)) {
        Logger::error("Record not found in vault: " + filename);
        return false;
    }

    int lockFdRaw = ::open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    UniqueFd lockFd(lockFdRaw);
    if (!lockFd.valid()) {
        Logger::error("Failed to open lock file for deletion: " + lockPath.string());
        return false;
    }

    FileLock fileLock(lockFd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
    if (!fileLock.isLocked()) {
        Logger::error("Cannot delete record " + filename + " (file is currently locked/in use)");
        return false;
    }

    std::filesystem::remove(recordPath, ec);
    if (ec) {
        Logger::error("Failed to remove vault record file: " + recordPath.string());
        return false;
    }

    lockFd.reset(-1);
    std::filesystem::remove(lockPath, ec);

    Logger::info("Successfully deleted vault record: " + filename);
    return true;
}

bool VaultManager::verifyRecord(const std::string& filename, std::string_view passphrase) {
    if (!isValidVaultFilename(filename) || filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        Logger::error("Invalid or prohibited vault filename: " + filename);
        return false;
    }

    std::error_code ec;
    const auto lockPath = getLockFilePath(filename);
    const auto srcRecordPath = getRecordFilePath(filename);
    if (lockPath.string().find("..") != std::string::npos || srcRecordPath.string().find("..") != std::string::npos) {
        Logger::error("Path traversal detected in vault paths");
        return false;
    }

    if (!std::filesystem::exists(srcRecordPath, ec)) {
        Logger::error("Encrypted record not found in vault: " + filename);
        return false;
    }

    // 1. Acquire POSIX advisory read lock (shared)
    int lockFdRaw = ::open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    UniqueFd lockFd(lockFdRaw);
    if (!lockFd.valid()) {
        Logger::error("Failed to open lock file: " + lockPath.string());
        return false;
    }

    FileLock fileLock(lockFd.get(), FileLock::LockType::Shared, FileLock::LockMode::NonBlocking);
    if (!fileLock.isLocked()) {
        Logger::error("Cannot acquire shared lock on: " + filename + " (file is currently in use)");
        return false;
    }

    // 2. Read VaultHeader
    std::ifstream recordFile(srcRecordPath, std::ios::binary);
    if (!recordFile) {
        Logger::error("Cannot open vault record for reading: " + srcRecordPath.string());
        return false;
    }

    VaultHeader rawHeader{};
    recordFile.read(reinterpret_cast<char*>(&rawHeader), sizeof(rawHeader));
    if (recordFile.gcount() != sizeof(rawHeader)) {
        Logger::error("Corrupted vault record: Incomplete header");
        return false;
    }

    // Decode Little-Endian wire format fields to host values
    const uint32_t magic = le32toh(rawHeader.magic);
    const uint32_t version = le32toh(rawHeader.version);
    const uint64_t original_size = le64toh(rawHeader.original_size);
    const uint64_t payload_size = le64toh(rawHeader.payload_size);

    const bool supportedMagic = magic == VAULT_MAGIC ||
        (magic == LEGACY_MAGIC && version == LEGACY_VAULT_VERSION);
    const bool supportedVersion = version == VAULT_VERSION ||
        version == VAULT_VERSION_V2 ||
        version == LEGACY_VAULT_VERSION;
    if (!supportedMagic || !supportedVersion) {
        Logger::error("Invalid vault file magic or incompatible version.");
        return false;
    }

    const uint64_t paddingSize = 16 - (original_size % 16);
    const bool payloadLengthOverflow = original_size != 0 &&
        original_size > std::numeric_limits<uint64_t>::max() - paddingSize;
    const uint64_t expectedPayloadSize = original_size == 0
        ? 0
        : (payloadLengthOverflow ? 0 : original_size + paddingSize);
    std::error_code fileSizeError;
    const uintmax_t recordFileSize = std::filesystem::file_size(srcRecordPath, fileSizeError);
    const bool recordLengthOverflow = payload_size >
        std::numeric_limits<uintmax_t>::max() - sizeof(VaultHeader);
    const uintmax_t expectedRecordSize = recordLengthOverflow
        ? 0
        : sizeof(VaultHeader) + static_cast<uintmax_t>(payload_size);
    if (fileSizeError || payloadLengthOverflow || recordLengthOverflow ||
        payload_size != expectedPayloadSize ||
        original_size > payload_size || recordFileSize != expectedRecordSize ||
        payload_size > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
        payload_size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        Logger::error("Invalid vault record lengths or trailing data");
        return false;
    }

    // 3. Derive Keys (dual keys for V3, single key for legacy V1/V2)
    std::span<const uint8_t, 16> saltSpan(rawHeader.salt, 16);
    PinnedMemory<32> encKey;
    PinnedMemory<32> macKey;

    if (version >= VAULT_VERSION) {
        if (!KeyDerivation::deriveDualKeysPbkdf2(passphrase, saltSpan, encKey.span(), macKey.span())) {
            Logger::error("Key derivation failed during verification");
            return false;
        }
    } else {
        if (!KeyDerivation::deriveKeyPbkdf2(passphrase, saltSpan, encKey.span())) {
            Logger::error("Key derivation failed during verification");
            return false;
        }
        std::memcpy(macKey.data(), encKey.data(), 32);
    }

    // 4. Streaming HMAC calculation
    std::array<uint8_t, 32> expectedHmac{};
    std::memcpy(expectedHmac.data(), rawHeader.hmac, 32);

    HmacContext hmacCtx;
    if (!hmacCtx.init(macKey.span())) {
        Logger::error("Failed to initialize streaming HMAC verification context");
        return false;
    }

    if (version != LEGACY_VAULT_VERSION) {
        VaultHeader authenticatedHeader = rawHeader;
        KeyDerivation::secureZero(authenticatedHeader.hmac, sizeof(authenticatedHeader.hmac));
        if (!hmacCtx.update(&authenticatedHeader, sizeof(authenticatedHeader))) {
            Logger::error("Failed to update HMAC with authenticated header");
            return false;
        }
        KeyDerivation::secureZero(&authenticatedHeader, sizeof(authenticatedHeader));
    }

    std::vector<uint8_t> streamChunk(CHUNK_SIZE);
    uint64_t bytesRemaining = payload_size;
    while (bytesRemaining > 0) {
        const size_t toRead = static_cast<size_t>(
            std::min(static_cast<uint64_t>(CHUNK_SIZE), bytesRemaining));
        recordFile.read(reinterpret_cast<char*>(streamChunk.data()), static_cast<std::streamsize>(toRead));
        if (static_cast<size_t>(recordFile.gcount()) != toRead) {
            Logger::error("Corrupted vault record: Incomplete payload data during verification");
            return false;
        }
        if (!hmacCtx.update(streamChunk.data(), toRead)) {
            Logger::error("Streaming HMAC update failed");
            return false;
        }
        bytesRemaining -= toRead;
    }

    const bool verified = hmacCtx.verifyConstantTime(expectedHmac);
    KeyDerivation::secureZero(streamChunk.data(), streamChunk.size());
    KeyDerivation::secureZero(&rawHeader, sizeof(rawHeader));

    if (!verified) {
        Logger::error("Cryptographic verification failed: Incorrect passphrase or tampered record for: " + filename);
        return false;
    }

    Logger::info("Cryptographic verification succeeded for: " + filename);
    return true;
}

bool VaultManager::shredFile(const std::filesystem::path& targetFile) {
    auto cleanTarget = targetFile.lexically_normal();
    if (cleanTarget.string().find("..") != std::string::npos) {
        Logger::error("Refusing to shred file with path traversal: " + targetFile.string());
        return false;
    }

    std::error_code ec;
    if (std::filesystem::is_symlink(cleanTarget, ec)) {
        Logger::error("Refusing to shred symbolic link: " + cleanTarget.string());
        return false;
    }

    if (!std::filesystem::exists(cleanTarget, ec) || !std::filesystem::is_regular_file(cleanTarget, ec)) {
        Logger::error("Target file does not exist or is not a regular file for shredding: " + cleanTarget.string());
        return false;
    }

    const uintmax_t fileSize = std::filesystem::file_size(cleanTarget, ec);
    if (ec) {
        Logger::error("Failed to query target file size before shredding");
        return false;
    }

    int fd = ::open(cleanTarget.c_str(), O_WRONLY | O_NOFOLLOW);
    if (fd < 0) {
        Logger::error("Failed to open file for shredding: " + cleanTarget.string());
        return false;
    }
    UniqueFd ufd(fd);

    if (fileSize > 0) {
        std::vector<uint8_t> buffer(CHUNK_SIZE);

        // Pass 1: Overwrite with cryptographic entropy from getrandom()
        uint64_t bytesRemaining = fileSize;
        while (bytesRemaining > 0) {
            const size_t chunkSize = static_cast<size_t>(
                std::min(static_cast<uint64_t>(CHUNK_SIZE), bytesRemaining));

            size_t entropyFilled = 0;
            while (entropyFilled < chunkSize) {
                ssize_t ret = ::getrandom(buffer.data() + entropyFilled, chunkSize - entropyFilled, 0);
                if (ret <= 0) {
                    for (size_t i = entropyFilled; i < chunkSize; ++i) {
                        buffer[i] = static_cast<uint8_t>(std::rand() & 0xFF);
                    }
                    break;
                }
                entropyFilled += static_cast<size_t>(ret);
            }

            ssize_t written = ::write(ufd.get(), buffer.data(), chunkSize);
            if (written != static_cast<ssize_t>(chunkSize)) {
                Logger::error("Write error during shredding pass 1 (entropy)");
                return false;
            }
            bytesRemaining -= chunkSize;
        }

        ::fsync(ufd.get());

        // Pass 2: Overwrite with all zeros
        if (::lseek(ufd.get(), 0, SEEK_SET) == static_cast<off_t>(-1)) {
            Logger::error("Lseek failed during shredding pass 2");
            return false;
        }

        std::fill(buffer.begin(), buffer.end(), 0x00);
        bytesRemaining = fileSize;
        while (bytesRemaining > 0) {
            const size_t chunkSize = static_cast<size_t>(
                std::min(static_cast<uint64_t>(CHUNK_SIZE), bytesRemaining));
            ssize_t written = ::write(ufd.get(), buffer.data(), chunkSize);
            if (written != static_cast<ssize_t>(chunkSize)) {
                Logger::error("Write error during shredding pass 2 (zeroization)");
                return false;
            }
            bytesRemaining -= chunkSize;
        }

        ::fsync(ufd.get());
        KeyDerivation::secureZero(buffer.data(), buffer.size());
    }

    ufd.reset(-1);
    std::filesystem::remove(cleanTarget, ec);
    if (ec) {
        Logger::error("Failed to unlink target file after shredding: " + cleanTarget.string());
        return false;
    }

    Logger::info("Successfully shredded and unlinked file: " + cleanTarget.string());
    return true;
}

/**
 * @brief Serializes a single filesystem entry (directory or regular file) into the directory archive pack.
 *
 * @param pack Output archive stream.
 * @param entry Filesystem directory entry to serialize.
 * @param cleanSrcDir Canonical base path of the source directory.
 * @param buffer Scratch buffer used for streaming file chunks.
 * @return true if the entry was successfully serialized, false if I/O error occurred.
 */
static bool writeDirectoryEntry(std::ofstream& pack,
                                const std::filesystem::directory_entry& entry,
                                const std::filesystem::path& cleanSrcDir,
                                std::vector<uint8_t>& buffer) {
    std::error_code ec;
    // Compute relative path within the archive hierarchy
    std::string relPath = std::filesystem::relative(entry.path(), cleanSrcDir, ec).generic_string();
    if (relPath.empty() || relPath == "." || relPath == "..") {
        return true;
    }

    struct stat st{};
    if (::stat(entry.path().c_str(), &st) != 0) {
        Logger::warn("Could not stat entry, skipping: " + entry.path().string());
        return true;
    }

    // Determine type tag (1: Directory, 2: Regular file)
    uint8_t type = 0;
    if (entry.is_directory(ec)) {
        type = 1;
    } else if (entry.is_regular_file(ec)) {
        type = 2;
    } else {
        return true;
    }

    uint16_t pathLen = static_cast<uint16_t>(relPath.size());
    uint32_t mode = static_cast<uint32_t>(st.st_mode & 07777);
    uint64_t mtime = static_cast<uint64_t>(st.st_mtime);
    uint64_t fileSize = (type == 2) ? static_cast<uint64_t>(st.st_size) : 0;

    // Convert metadata fields to little-endian byte order
    uint16_t pathLenLe = htole16(pathLen);
    uint32_t modeLe = htole32(mode);
    uint64_t mtimeLe = htole64(mtime);
    uint64_t fileSizeLe = htole64(fileSize);

    pack.write(reinterpret_cast<const char*>(&type), sizeof(type));
    pack.write(reinterpret_cast<const char*>(&pathLenLe), sizeof(pathLenLe));
    pack.write(relPath.data(), pathLen);
    pack.write(reinterpret_cast<const char*>(&modeLe), sizeof(modeLe));
    pack.write(reinterpret_cast<const char*>(&mtimeLe), sizeof(mtimeLe));
    pack.write(reinterpret_cast<const char*>(&fileSizeLe), sizeof(fileSizeLe));

    // Stream regular file contents in 64 KiB chunks
    if (type == 2 && fileSize > 0) {
        std::ifstream fileIn(entry.path(), std::ios::binary);
        if (!fileIn) {
            Logger::error("Failed to read file in directory: " + entry.path().string());
            return false;
        }
        uint64_t remaining = fileSize;
        while (remaining > 0) {
            const size_t toRead = static_cast<size_t>(
                std::min(static_cast<uint64_t>(VaultManager::CHUNK_SIZE), remaining));
            fileIn.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(toRead));
            if (static_cast<size_t>(fileIn.gcount()) != toRead) {
                Logger::error("File read error while packing: " + entry.path().string());
                return false;
            }
            pack.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(toRead));
            remaining -= toRead;
        }
    }
    return true;
}

/**
 * @brief Archives and encrypts an entire directory tree into a single authenticated vault record.
 *
 * @param srcDir Path to the local directory to archive and encrypt.
 * @param passphrase Secret user passphrase used to derive cryptographic keys.
 * @param recordName Optional vault record name (defaults to srcDir folder name with .kvdir suffix).
 * @return true if the directory was successfully archived, encrypted, and written atomically.
 * @return false if validation failed, filesystem errors occurred, or encryption aborted.
 *
 * @details Traverses directory entries preserving POSIX modes and timestamps into the KVDIR1
 * binary pack format, enforcing strict path normalization, before streaming through AES-256-CBC.
 */
bool VaultManager::encryptDirectory(const std::filesystem::path& srcDir,
                                    std::string_view passphrase,
                                    const std::string& recordName) {
    std::error_code ec;
    auto cleanSrcDir = srcDir.lexically_normal();
    if (cleanSrcDir.string().find("..") != std::string::npos) {
        Logger::error("Path traversal detected in source directory: " + srcDir.string());
        return false;
    }
    if (std::filesystem::is_symlink(cleanSrcDir, ec)) {
        Logger::error("Source directory cannot be a symbolic link: " + cleanSrcDir.string());
        return false;
    }
    if (!std::filesystem::exists(cleanSrcDir, ec) || !std::filesystem::is_directory(cleanSrcDir, ec)) {
        Logger::error("Source directory does not exist or is not a directory: " + cleanSrcDir.string());
        return false;
    }

    std::string recName = recordName.empty() ? cleanSrcDir.filename().string() : recordName;
    if (recName.empty()) {
        recName = "root_dir";
    }
    if (!recName.ends_with(".kvdir")) {
        recName += ".kvdir";
    }

    std::string safeRecName = std::filesystem::path(recName).filename().string();
    if (!isValidVaultFilename(safeRecName) || safeRecName.find("..") != std::string::npos || safeRecName.find('/') != std::string::npos) {
        Logger::error("Invalid record name for directory archive: " + recName);
        return false;
    }

    const std::filesystem::path tempPackPath = (m_vaultPath / (".pack_" + std::to_string(::getpid()) + "_" + safeRecName)).lexically_normal();
    if (tempPackPath.string().find("..") != std::string::npos) {
        Logger::error("Unsafe temporary archive path: " + tempPackPath.string());
        return false;
    }
    std::ofstream pack(tempPackPath, std::ios::binary | std::ios::trunc);
    if (!pack) {
        Logger::error("Failed to create temporary directory archive: " + tempPackPath.string());
        return false;
    }
    ::chmod(tempPackPath.c_str(), 0600);

    const char magicHeader[6] = {'K', 'V', 'D', 'I', 'R', '1'};
    pack.write(magicHeader, sizeof(magicHeader));

    std::vector<uint8_t> buffer(CHUNK_SIZE);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(cleanSrcDir, ec)) {
        if (entry.is_symlink(ec)) {
            Logger::warn("Skipping symbolic link in directory tree: " + entry.path().string());
            continue;
        }
        if (!writeDirectoryEntry(pack, entry, cleanSrcDir, buffer)) {
            pack.close();
            shredFile(tempPackPath);
            return false;
        }
    }

    pack.flush();
    pack.close();

    const std::filesystem::path namedTempPack = (m_vaultPath / safeRecName).lexically_normal();
    if (namedTempPack.string().find("..") != std::string::npos) {
        Logger::error("Unsafe destination archive pack path");
        shredFile(tempPackPath);
        return false;
    }

    std::filesystem::rename(tempPackPath, namedTempPack, ec);
    if (ec) {
        Logger::error("Failed to rename temporary directory pack: " + ec.message());
        shredFile(tempPackPath);
        return false;
    }

    bool success = encryptFile(namedTempPack, passphrase);
    shredFile(namedTempPack);

    if (success) {
        Logger::info("Successfully encrypted directory " + cleanSrcDir.string() + " as vault record: " + safeRecName);
    }
    return success;
}

/**
 * @brief Unpacks a single directory or file entry from the archive pack stream.
 *
 * @param pack Input stream of the decrypted directory pack.
 * @param cleanDestDir Target root directory for extraction.
 * @param buffer Scratch buffer for streaming file data.
 * @param hasMore Output boolean set to true if another entry remains, false if at EOF.
 * @return true if the entry was unpacked successfully, false if corrupted or traversal detected.
 */
static bool unpackDirectoryEntry(std::ifstream& pack,
                                 const std::filesystem::path& cleanDestDir,
                                 std::vector<uint8_t>& buffer,
                                 bool& hasMore) {
    hasMore = false;
    if (pack.peek() == EOF) {
        return true;
    }

    uint8_t type = 0;
    uint16_t pathLenLe = 0;
    if (!pack.read(reinterpret_cast<char*>(&type), sizeof(type))) return true;
    if (!pack.read(reinterpret_cast<char*>(&pathLenLe), sizeof(pathLenLe))) {
        return false;
    }
    uint16_t pathLen = le16toh(pathLenLe);
    if (pathLen == 0 || pathLen > 4096) {
        return false;
    }

    std::string relPath(pathLen, '\0');
    pack.read(relPath.data(), pathLen);

    // Validate path boundaries against directory traversal
    if (relPath.find("..") != std::string::npos || relPath.front() == '/' || relPath.front() == '\\') {
        Logger::error("Refusing to unpack entry with unsafe path: " + relPath);
        return false;
    }

    uint32_t modeLe = 0;
    uint64_t mtimeLe = 0;
    uint64_t fileSizeLe = 0;
    pack.read(reinterpret_cast<char*>(&modeLe), sizeof(modeLe));
    pack.read(reinterpret_cast<char*>(&mtimeLe), sizeof(mtimeLe));
    pack.read(reinterpret_cast<char*>(&fileSizeLe), sizeof(fileSizeLe));

    uint32_t mode = le32toh(modeLe);
    uint64_t mtime = le64toh(mtimeLe);
    uint64_t fileSize = le64toh(fileSizeLe);

    std::error_code ec;
    const std::filesystem::path target = (cleanDestDir / relPath).lexically_normal();
    auto relCheck = std::filesystem::relative(target, cleanDestDir, ec);
    if (relCheck.empty() || relCheck.string().starts_with("..") || relCheck.is_absolute() || target.string().find("..") != std::string::npos) {
        Logger::error("Path traversal attempt in archive: " + relPath);
        return false;
    }

    if (type == 1) { // Directory
        std::filesystem::create_directories(target, ec);
        if (mode != 0) {
            ::chmod(target.c_str(), static_cast<mode_t>(mode & 07777));
        }
    } else if (type == 2) { // File
        std::filesystem::create_directories(target.parent_path(), ec);
        std::ofstream fileOut(target, std::ios::binary | std::ios::trunc);
        if (!fileOut) {
            Logger::error("Cannot create destination file: " + target.string());
            return false;
        }

        uint64_t remaining = fileSize;
        while (remaining > 0) {
            const size_t toRead = static_cast<size_t>(
                std::min(static_cast<uint64_t>(VaultManager::CHUNK_SIZE), remaining));
            pack.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(toRead));
            if (static_cast<size_t>(pack.gcount()) != toRead) {
                Logger::error("Corrupted archive data while unpacking: " + target.string());
                return false;
            }
            fileOut.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(toRead));
            remaining -= toRead;
        }
        fileOut.close();

        if (mode != 0) {
            ::chmod(target.c_str(), static_cast<mode_t>(mode & 07777));
        }
        if (mtime != 0) {
            struct timespec times[2];
            times[0].tv_sec = static_cast<time_t>(mtime);
            times[0].tv_nsec = 0;
            times[1].tv_sec = static_cast<time_t>(mtime);
            times[1].tv_nsec = 0;
            ::utimensat(AT_FDCWD, target.c_str(), times, 0);
        }
    }

    hasMore = true;
    return true;
}

/**
 * @brief Decrypts and unpacks a directory archive record into a specified destination directory.
 *
 * @param recordName Name of the encrypted directory vault record.
 * @param destDir Target directory where the archive contents will be extracted.
 * @param passphrase Secret user passphrase used for authentication and decryption.
 * @return true if the archive was cryptographically verified, decrypted, and extracted without errors.
 * @return false if the record was not found, passphrase was incorrect, or path traversal was detected.
 *
 * @details Performs streaming authenticated decryption of the record into a temporary container,
 * verifies the KVDIR1 magic signature, checks all relative file paths against directory traversal (Zip-Slip),
 * creates destination subdirectories, extracts files, and restores original POSIX permissions and mtimes.
 */
bool VaultManager::decryptDirectory(const std::string& recordName,
                                    const std::filesystem::path& destDir,
                                    std::string_view passphrase) {
    std::string actualRec = std::filesystem::path(recordName).filename().string();
    if (!isValidVaultFilename(actualRec) || actualRec.find("..") != std::string::npos || actualRec.find('/') != std::string::npos) {
        Logger::error("Invalid or unsafe record name: " + recordName);
        return false;
    }

    auto cleanDestDir = destDir.lexically_normal();
    if (cleanDestDir.string().find("..") != std::string::npos) {
        Logger::error("Path traversal detected in destination directory: " + destDir.string());
        return false;
    }

    std::error_code ec;
    if (!std::filesystem::exists(getRecordFilePath(actualRec), ec)) {
        if (!actualRec.ends_with(".kvdir") && std::filesystem::exists(getRecordFilePath(actualRec + ".kvdir"), ec)) {
            actualRec += ".kvdir";
        } else {
            Logger::error("Directory archive record not found: " + recordName);
            return false;
        }
    }

    if (!std::filesystem::exists(cleanDestDir, ec)) {
        std::filesystem::create_directories(cleanDestDir, ec);
        if (ec) {
            Logger::error("Failed to create destination directory: " + cleanDestDir.string());
            return false;
        }
    }

    const std::filesystem::path tempUnpack = (cleanDestDir / (".unpack_" + std::to_string(::getpid()) + "_" + actualRec)).lexically_normal();
    if (tempUnpack.string().find("..") != std::string::npos) {
        Logger::error("Unsafe temporary unpack path");
        return false;
    }

    if (!decryptFile(actualRec, tempUnpack, passphrase)) {
        Logger::error("Failed to decrypt directory record: " + actualRec);
        shredFile(tempUnpack);
        return false;
    }

    std::ifstream pack(tempUnpack, std::ios::binary);
    if (!pack) {
        Logger::error("Failed to open decrypted archive pack: " + tempUnpack.string());
        shredFile(tempUnpack);
        return false;
    }

    char magic[6] = {0};
    pack.read(magic, 6);
    if (std::memcmp(magic, "KVDIR1", 6) != 0) {
        Logger::error("Corrupted directory archive format or unrecognized version in: " + actualRec);
        pack.close();
        shredFile(tempUnpack);
        return false;
    }

    std::vector<uint8_t> buffer(CHUNK_SIZE);
    bool extractSuccess = true;
    bool hasMore = true;

    while (hasMore) {
        if (!unpackDirectoryEntry(pack, cleanDestDir, buffer, hasMore)) {
            extractSuccess = false;
            break;
        }
    }

    pack.close();
    shredFile(tempUnpack);

    if (extractSuccess) {
        Logger::info("Successfully restored directory archive " + actualRec + " to: " + cleanDestDir.string());
    } else {
        Logger::error("Directory archive extraction failed for: " + actualRec);
    }

    return extractSuccess;
}

size_t VaultManager::pruneStaleLocks() {
    size_t prunedCount = 0;
    std::error_code ec;
    if (!std::filesystem::exists(m_locksPath, ec)) {
        return 0;
    }

    for (const auto& entry : std::filesystem::directory_iterator(m_locksPath, ec)) {
        if (!entry.is_regular_file(ec) || entry.path().extension() != ".lock") {
            continue;
        }

        int fd = ::open(entry.path().c_str(), O_RDWR);
        if (fd < 0) {
            continue;
        }

        UniqueFd lockFd(fd);
        FileLock lock(lockFd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
        if (lock.isLocked()) {
            std::filesystem::remove(entry.path(), ec);
            if (!ec) {
                prunedCount++;
            }
        }
    }
    return prunedCount;
}

VaultStatus VaultManager::inspectStatus() {
    VaultStatus status;
    status.vault_path = m_vaultPath;
    status.is_initialized = std::filesystem::exists(m_metaPath);

    if (status.is_initialized && std::filesystem::exists(m_recordsPath)) {
        for (const auto& entry : std::filesystem::directory_iterator(m_recordsPath)) {
            if (entry.is_regular_file() && entry.path().extension() == ".enc") {
                status.stored_files.push_back(entry.path().stem().string());
                status.total_vault_bytes += entry.file_size();
            }
        }
        status.file_count = status.stored_files.size();
        status.stale_locks_pruned = pruneStaleLocks();
    }

    // Inspect kernel driver status
    UniqueFd devFd = openKernelDevice();
    if (devFd.valid()) {
        status.kernel_driver_available = true;
        struct kvault_status_param kstatus{};
        if (::ioctl(devFd.get(), KVAULT_IOCTL_GET_STATUS, &kstatus) == 0) {
            status.kernel_driver_version = kstatus.driver_version;
            status.kernel_bytes_transformed = kstatus.bytes_transformed;
        }
    } else {
        status.kernel_driver_available = false;
    }

    return status;
}

bool VaultManager::isKernelDriverLoaded() const {
    return std::filesystem::exists("/dev/kvault");
}

std::vector<BenchmarkMetric> VaultManager::runBenchmark(size_t streamSizeBytes) {
    std::vector<BenchmarkMetric> metrics;
    if (streamSizeBytes == 0) streamSizeBytes = 16 * 1024 * 1024;

    UniqueFd devFd = openKernelDevice();
    const bool hasKernel = devFd.valid();
    const std::string cipherBackend = hasKernel ? "/dev/kvault (Kernel)" : "Software (C++20)";

    // 1. PBKDF2 Key Derivation
    {
        std::string_view pass = "BenchmarkSecretPassphrase2026!";
        std::array<uint8_t, 16> salt{};
        KeyDerivation::generateSalt(salt);

        PinnedMemory<32> encKey;
        PinnedMemory<32> macKey;

        auto t0 = std::chrono::steady_clock::now();
        KeyDerivation::deriveDualKeysPbkdf2(pass, salt, encKey.span(), macKey.span(), KeyDerivation::DEFAULT_ITERATIONS);
        auto t1 = std::chrono::steady_clock::now();

        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        metrics.push_back({
            "PBKDF2-HMAC-SHA256",
            "100,000 rounds (dual 256-bit keys)",
            ms,
            (ms > 0.0) ? (100000.0 / (ms / 1000.0)) : 0.0,
            "User-space (RFC 2898)"
        });
    }

    // Setup buffers
    PinnedMemory<32> encKey;
    PinnedMemory<32> macKey;
    for (size_t i = 0; i < 32; ++i) {
        encKey.span()[i] = static_cast<uint8_t>(i ^ 0x5a);
        macKey.span()[i] = static_cast<uint8_t>(i ^ 0xa5);
    }
    std::array<uint8_t, 16> iv{};
    for (size_t i = 0; i < 16; ++i) iv[i] = static_cast<uint8_t>(i ^ 0x3c);

    const size_t chunkSize = CHUNK_SIZE;
    std::vector<uint8_t> chunk(chunkSize, 0x42);
    std::vector<uint8_t> cipherChunk;
    const size_t totalChunks = (streamSizeBytes + chunkSize - 1) / chunkSize;
    const size_t actualTotalBytes = totalChunks * chunkSize;

    // 2. AES-256-CBC Encryption
    {
        std::array<uint8_t, 16> runningIv = iv;
        if (hasKernel) {
            configureKernelSession(devFd.get(), encKey.span(), runningIv, KVAULT_MODE_ENCRYPT);
        }

        auto t0 = std::chrono::steady_clock::now();
        for (size_t c = 0; c < totalChunks; ++c) {
            transformBuffer(devFd.get(), chunk, cipherChunk, encKey.span(), runningIv, true);
        }
        auto t1 = std::chrono::steady_clock::now();

        if (hasKernel) flushKernelSession(devFd.get());

        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double throughput = (ms > 0.0) ? ((static_cast<double>(actualTotalBytes) / 1000000.0) / (ms / 1000.0)) : 0.0;

        metrics.push_back({
            "AES-256-CBC Encryption",
            std::to_string(actualTotalBytes / (1024 * 1024)) + " MiB (" + std::to_string(chunkSize / 1024) + " KiB chunks)",
            ms,
            throughput,
            cipherBackend
        });
    }

    // 3. AES-256-CBC Decryption
    {
        std::array<uint8_t, 16> runningIv = iv;
        if (hasKernel) {
            configureKernelSession(devFd.get(), encKey.span(), runningIv, KVAULT_MODE_DECRYPT);
        }

        auto t0 = std::chrono::steady_clock::now();
        for (size_t c = 0; c < totalChunks; ++c) {
            transformBuffer(devFd.get(), cipherChunk, chunk, encKey.span(), runningIv, false);
        }
        auto t1 = std::chrono::steady_clock::now();

        if (hasKernel) flushKernelSession(devFd.get());

        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double throughput = (ms > 0.0) ? ((static_cast<double>(actualTotalBytes) / 1000000.0) / (ms / 1000.0)) : 0.0;

        metrics.push_back({
            "AES-256-CBC Decryption",
            std::to_string(actualTotalBytes / (1024 * 1024)) + " MiB (" + std::to_string(chunkSize / 1024) + " KiB chunks)",
            ms,
            throughput,
            cipherBackend
        });
    }

    // 4. Streaming HMAC-SHA256
    {
        HmacContext hmacCtx;
        hmacCtx.init(macKey.span());
        std::array<uint8_t, 32> tag{};

        auto t0 = std::chrono::steady_clock::now();
        for (size_t c = 0; c < totalChunks; ++c) {
            hmacCtx.update(chunk);
        }
        hmacCtx.finalize(tag);
        auto t1 = std::chrono::steady_clock::now();

        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double throughput = (ms > 0.0) ? ((static_cast<double>(actualTotalBytes) / 1000000.0) / (ms / 1000.0)) : 0.0;

        metrics.push_back({
            "HMAC-SHA256 Streaming",
            std::to_string(actualTotalBytes / (1024 * 1024)) + " MiB continuous digest",
            ms,
            throughput,
            "User-space (Streaming O(1) RAM)"
        });
    }

    // 5. Full Pipeline (Enc + MAC)
    {
        std::array<uint8_t, 16> runningIv = iv;
        if (hasKernel) {
            configureKernelSession(devFd.get(), encKey.span(), runningIv, KVAULT_MODE_ENCRYPT);
        }
        HmacContext hmacCtx;
        hmacCtx.init(macKey.span());
        std::array<uint8_t, 32> tag{};

        auto t0 = std::chrono::steady_clock::now();
        for (size_t c = 0; c < totalChunks; ++c) {
            transformBuffer(devFd.get(), chunk, cipherChunk, encKey.span(), runningIv, true);
            hmacCtx.update(cipherChunk);
        }
        hmacCtx.finalize(tag);
        auto t1 = std::chrono::steady_clock::now();

        if (hasKernel) flushKernelSession(devFd.get());

        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double throughput = (ms > 0.0) ? ((static_cast<double>(actualTotalBytes) / 1000000.0) / (ms / 1000.0)) : 0.0;

        metrics.push_back({
            "Full Pipeline (Enc + MAC)",
            std::to_string(actualTotalBytes / (1024 * 1024)) + " MiB streaming pipeline",
            ms,
            throughput,
            cipherBackend + " + HMAC"
        });
    }

    // Scrub all local buffers
    KeyDerivation::secureZero(chunk.data(), chunk.size());
    KeyDerivation::secureZero(cipherChunk.data(), cipherChunk.size());
    KeyDerivation::secureZero(iv.data(), iv.size());

    return metrics;
}

} // namespace kvault
