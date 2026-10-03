/**
 * @file VaultManager.hpp
 * @brief High-level vault header, chunking, locking, and storage orchestration for kvault.
 */

#ifndef VAULT_MANAGER_HPP
#define VAULT_MANAGER_HPP

#include "UniqueFd.hpp"
#include "FileLock.hpp"
#include "AtomicFileWriter.hpp"
#include "KeyDerivation.hpp"
#include "PinnedMemory.hpp"
#include "kvault_ioctl.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <memory>

namespace kvault {

#pragma pack(push, 1)
/**
 * @struct VaultHeader
 * @brief 96-byte authenticated binary header prepended to every encrypted vault file.
 */
struct VaultHeader {
    uint32_t magic;          /**< Constant magic identifier 'KVLT' (0x4B564C54) */
    uint32_t version;        /**< Format version (0x00000003) */
    uint8_t  salt[16];       /**< Cryptographic salt for PBKDF2 */
    uint8_t  iv[16];         /**< AES-256-CBC Initialization Vector */
    uint64_t original_size;  /**< Unpadded plaintext size in bytes */
    uint64_t payload_size;   /**< Total encrypted payload size in bytes */
    uint8_t  hmac[32];       /**< SHA-256 HMAC authentication tag */
    uint32_t posix_mode;     /**< POSIX file mode / permissions (st_mode & 07777) */
    uint32_t mtime_epoch;    /**< Modification timestamp (seconds since Unix epoch) */
};
#pragma pack(pop)

static_assert(sizeof(VaultHeader) == 96, "VaultHeader must be exactly 96 bytes");

/**
 * @struct VaultRecordInfo
 * @brief Detailed metadata record for files stored in the vault.
 */
struct VaultRecordInfo {
    std::string filename;
    uint32_t version{0};
    uint64_t original_size{0};
    uint64_t payload_size{0};
    uint32_t posix_mode{0};
    uint32_t mtime_epoch{0};
    bool is_locked{false};
};

/**
 * @struct VaultStatus
 * @brief Information structure for vault health and metrics.
 */
struct VaultStatus {
    bool is_initialized{false};
    std::filesystem::path vault_path;
    size_t file_count{0};
    uint64_t total_vault_bytes{0};
    bool kernel_driver_available{false};
    uint32_t kernel_driver_version{0};
    uint64_t kernel_bytes_transformed{0};
    size_t stale_locks_pruned{0};
    std::vector<std::string> stored_files;
};

/**
 * @class VaultManager
 * @brief Core orchestrator for secure file storage, encryption, and decryption.
 */
class VaultManager {
public:
    static constexpr uint32_t VAULT_MAGIC = 0x4B564C54; // "KVLT"
    static constexpr uint32_t LEGACY_MAGIC = 0x53454356; // "SECV"
    static constexpr uint32_t VAULT_VERSION = 3;         // Version 3: Dual derived keys + Canonical Endianness
    static constexpr uint32_t VAULT_VERSION_V2 = 2;      // Version 2: Single derived key + Authenticated Header
    static constexpr uint32_t LEGACY_VAULT_VERSION = 1;  // Version 1: Legacy payload-only HMAC
    static constexpr size_t CHUNK_SIZE = 64 * 1024; // 64 KiB streaming chunks

    /**
     * @brief Constructs a VaultManager managing the specified vault directory.
     * @param vaultPath Directory path to vault.
     */
    explicit VaultManager(std::filesystem::path vaultPath);

    /**
     * @brief Destructor. Ensures device and locks are released cleanly.
     */
    ~VaultManager() noexcept;

    // Non-copyable
    VaultManager(const VaultManager&) = delete;
    VaultManager& operator=(const VaultManager&) = delete;
    VaultManager(VaultManager&&) noexcept = default;
    VaultManager& operator=(VaultManager&&) noexcept = default;

    /**
     * @brief Initializes a new secure vault directory with 0700 permissions and metadata.
     * @return True on success, false if already initialized or permissions fail.
     */
    bool initializeVault();

    /**
     * @brief Encrypts a source file and stores it atomically inside the vault.
     * @param srcFile Path to plaintext source file.
     * @param passphrase User passphrase for key derivation.
     * @return True on success, false otherwise.
     */
    bool encryptFile(const std::filesystem::path& srcFile, std::string_view passphrase);

    /**
     * @brief Decrypts a vault record and restores it to the destination file.
     * @param filename Base filename of file stored in vault.
     * @param destFile Target path to write recovered plaintext.
     * @param passphrase User passphrase for key derivation.
     * @return True on success, false if authentication or decryption fails.
     */
    bool decryptFile(const std::string& filename,
                     const std::filesystem::path& destFile,
                     std::string_view passphrase);

    /**
     * @brief Lists all stored records in the vault with their sizes, permissions, and lock state.
     * @return Vector of VaultRecordInfo entries.
     */
    [[nodiscard]] std::vector<VaultRecordInfo> listRecords();

    /**
     * @brief Safely removes a record and its lockfile under exclusive lock.
     * @param filename Base filename of record in vault.
     * @return True on success, false if file does not exist, locked, or error.
     */
    bool deleteRecord(const std::string& filename);

    /**
     * @brief Cryptographically verifies a vault record's HMAC integrity in-place without disk extraction.
     * @param filename Base filename of file stored in vault.
     * @param passphrase User passphrase for key derivation.
     * @return True if authentication succeeds, false otherwise.
     */
    bool verifyRecord(const std::string& filename, std::string_view passphrase);

    /**
     * @brief Securely shreds a plaintext file on disk using multi-pass entropy + zeroization + fsync before unlinking.
     * @param targetFile Path to file to shred.
     * @return True on success, false if file could not be opened/overwritten.
     */
    static bool shredFile(const std::filesystem::path& targetFile);

    /**
     * @brief Encrypts an entire directory tree recursively into an authenticated vault record.
     * @param srcDir Path to directory to pack and encrypt.
     * @param passphrase Passphrase for key derivation.
     * @param recordName Optional custom vault record name (defaults to folder stem).
     * @return True on success, false otherwise.
     */
    bool encryptDirectory(const std::filesystem::path& srcDir,
                          std::string_view passphrase,
                          const std::string& recordName = "");

    /**
     * @brief Authenticates and unpacks a directory archive from the vault into the target directory.
     * @param recordName Name of vault record.
     * @param destDir Target directory to restore tree into.
     * @param passphrase Passphrase for key derivation.
     * @return True on success, false if authentication or extraction fails.
     */
    bool decryptDirectory(const std::string& recordName,
                          const std::filesystem::path& destDir,
                          std::string_view passphrase);

    /**
     * @brief Prunes and unlinks abandoned lock files not currently held by active processes.
     * @return Number of stale lock files garbage-collected.
     */
    size_t pruneStaleLocks();

    /**
     * @brief Inspects vault statistics, active locks, and kernel accelerator health.
     * @return VaultStatus structure with diagnostic details.
     */
    [[nodiscard]] VaultStatus inspectStatus();

    /**
     * @brief Checks if the kernel acceleration driver /dev/kvault is available.
     */
    [[nodiscard]] bool isKernelDriverLoaded() const;

private:
    std::filesystem::path m_vaultPath;
    std::filesystem::path m_recordsPath;
    std::filesystem::path m_locksPath;
    std::filesystem::path m_metaPath;

    UniqueFd openKernelDevice();
    bool configureKernelSession(int devFd,
                                std::span<const uint8_t, 32> key,
                                std::span<const uint8_t, 16> iv,
                                int mode);
    void flushKernelSession(int devFd);

    // Cryptographic transformation engine: uses kernel device if fd >= 0, or fallback
    bool transformBuffer(int devFd,
                         std::span<const uint8_t> input,
                         std::vector<uint8_t>& output,
                         std::span<const uint8_t, 32> key,
                         std::span<uint8_t, 16> iv,
                         bool encrypt);

    std::filesystem::path getLockFilePath(const std::string& filename) const;
    std::filesystem::path getRecordFilePath(const std::string& filename) const;
};

} // namespace kvault


#endif // VAULT_MANAGER_HPP
