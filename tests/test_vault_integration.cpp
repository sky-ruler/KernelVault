/**
 * @file test_vault_integration.cpp
 * @brief End-to-end integration and round-trip tests for VaultManager in kvault.
 */

#include "VaultManager.hpp"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>

using namespace kvault;

class VaultIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_vaultDir = std::filesystem::temp_directory_path() / "kvault_test_vault";
        m_scratchDir = std::filesystem::temp_directory_path() / "kvault_test_scratch";

        std::filesystem::remove_all(m_vaultDir);
        std::filesystem::remove_all(m_scratchDir);

        std::filesystem::create_directories(m_scratchDir);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_vaultDir, ec);
        std::filesystem::remove_all(m_scratchDir, ec);
    }

    std::filesystem::path createDummyFile(const std::string& name, size_t sizeBytes) {
        auto p = m_scratchDir / name;
        std::ofstream ofs(p, std::ios::binary);
        std::vector<uint8_t> buffer(sizeBytes);
        for (size_t i = 0; i < sizeBytes; ++i) {
            buffer[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
        }
        ofs.write(reinterpret_cast<const char*>(buffer.data()),
                  static_cast<std::streamsize>(buffer.size()));
        return p;
    }

    std::filesystem::path m_vaultDir;
    std::filesystem::path m_scratchDir;
};

TEST_F(VaultIntegrationTest, VaultInitializationLifecycle) {
    VaultManager vault(m_vaultDir);
    EXPECT_TRUE(vault.initializeVault());

    // Second initialization should fail (idempotency guard)
    EXPECT_FALSE(vault.initializeVault());

    auto status = vault.inspectStatus();
    EXPECT_TRUE(status.is_initialized);
    EXPECT_EQ(status.file_count, 0);
}

TEST_F(VaultIntegrationTest, EncryptDecryptRoundTripSmallFile) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "confidential.txt";
    auto sourcePath = createDummyFile(testFilename, 1024); // 1 KiB
    std::string passphrase = "CorrectHorseBatteryStaple2026!";

    // Encrypt
    ASSERT_TRUE(vault.encryptFile(sourcePath, passphrase));

    auto status = vault.inspectStatus();
    EXPECT_EQ(status.file_count, 1);
    EXPECT_GT(status.total_vault_bytes, 1024);

    // Decrypt
    auto restoredPath = m_scratchDir / "restored.txt";
    ASSERT_TRUE(vault.decryptFile(testFilename, restoredPath, passphrase));

    // Verify bit-for-bit equality
    EXPECT_EQ(std::filesystem::file_size(sourcePath), std::filesystem::file_size(restoredPath));

    std::ifstream orig(sourcePath, std::ios::binary);
    std::ifstream rest(restoredPath, std::ios::binary);

    std::vector<uint8_t> origData((std::istreambuf_iterator<char>(orig)), {});
    std::vector<uint8_t> restData((std::istreambuf_iterator<char>(rest)), {});

    EXPECT_EQ(origData, restData);
}

TEST_F(VaultIntegrationTest, EncryptDecryptMultiChunkLargeFile) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    // 150 KiB spans across 3 * 64 KiB chunks, validating streaming & PKCS#7 padding
    std::string testFilename = "large_payload.bin";
    auto sourcePath = createDummyFile(testFilename, 150 * 1024);
    std::string passphrase = "MultiChunkStreamingPassphrase#1";

    ASSERT_TRUE(vault.encryptFile(sourcePath, passphrase));

    auto restoredPath = m_scratchDir / "large_restored.bin";
    ASSERT_TRUE(vault.decryptFile(testFilename, restoredPath, passphrase));

    EXPECT_EQ(std::filesystem::file_size(sourcePath), std::filesystem::file_size(restoredPath));

    std::ifstream orig(sourcePath, std::ios::binary);
    std::ifstream rest(restoredPath, std::ios::binary);

    std::vector<uint8_t> origData((std::istreambuf_iterator<char>(orig)), {});
    std::vector<uint8_t> restData((std::istreambuf_iterator<char>(rest)), {});

    EXPECT_EQ(origData, restData);
}

TEST_F(VaultIntegrationTest, RejectIncorrectPassphrase) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "secret.doc";
    auto sourcePath = createDummyFile(testFilename, 512);
    std::string realPass = "RealPassphrase123";
    std::string wrongPass = "WrongPassphrase999";

    ASSERT_TRUE(vault.encryptFile(sourcePath, realPass));

    auto restoredPath = m_scratchDir / "never_created.doc";
    EXPECT_FALSE(vault.decryptFile(testFilename, restoredPath, wrongPass));
    EXPECT_FALSE(std::filesystem::exists(restoredPath));
}

TEST_F(VaultIntegrationTest, RejectTamperedCiphertext) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "unaltered.bin";
    auto sourcePath = createDummyFile(testFilename, 256);
    std::string pass = "SecureMasterPassword#1";

    ASSERT_TRUE(vault.encryptFile(sourcePath, pass));

    // Tamper with record file in vault
    auto recordPath = m_vaultDir / "records" / (testFilename + ".enc");
    ASSERT_TRUE(std::filesystem::exists(recordPath));

    {
        std::fstream stream(recordPath, std::ios::in | std::ios::out | std::ios::binary);
        // Tamper with a payload byte past the 96-byte header
        stream.seekg(105);
        char b = 0;
        stream.read(&b, 1);
        b = static_cast<char>(static_cast<unsigned char>(b) ^ 0xFFU); // Flip all bits
        stream.seekp(105);
        stream.write(&b, 1);
    }

    auto restoredPath = m_scratchDir / "tampered_restored.bin";
    EXPECT_FALSE(vault.decryptFile(testFilename, restoredPath, pass));
    EXPECT_FALSE(std::filesystem::exists(restoredPath));
}

TEST_F(VaultIntegrationTest, RejectTamperedHeader) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    const std::string testFilename = "header_integrity.bin";
    const auto sourcePath = createDummyFile(testFilename, 256);
    const std::string passphrase = "HeaderIntegrityPassphrase#1";
    ASSERT_TRUE(vault.encryptFile(sourcePath, passphrase));

    const auto recordPath = m_vaultDir / "records" / (testFilename + ".enc");
    {
        std::fstream stream(recordPath, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(stream.good());
        stream.seekg(24); // First IV byte in the 96-byte record header.
        char byte = 0;
        stream.read(&byte, 1);
        ASSERT_TRUE(stream.good());
        byte = static_cast<char>(static_cast<unsigned char>(byte) ^ 0x01U);
        stream.seekp(24);
        stream.write(&byte, 1);
        ASSERT_TRUE(stream.good());
    }

    const auto restoredPath = m_scratchDir / "header_tampered_restored.bin";
    EXPECT_FALSE(vault.decryptFile(testFilename, restoredPath, passphrase));
    EXPECT_FALSE(std::filesystem::exists(restoredPath));
}

TEST(KeyDerivationTest, PinnedMemoryLifecycleAndZeroing) {
    {
        PinnedMemory<32> mem;
        EXPECT_EQ(mem.size(), 32U);
        EXPECT_NE(mem.data(), nullptr);
        std::memset(mem.data(), 0xAA, 32);
        EXPECT_EQ(mem[0], 0xAA);
        EXPECT_EQ(mem[31], 0xAA);
    } // Desctructor runs secureZero and munlock
}

TEST(KeyDerivationTest, DualKeyDerivationIndependence) {
    std::string passphrase = "CorrectHorseBatteryStaple";
    std::array<uint8_t, 16> salt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    PinnedMemory<32> encKey;
    PinnedMemory<32> macKey;

    ASSERT_TRUE(KeyDerivation::deriveDualKeysPbkdf2(passphrase, salt, encKey.span(), macKey.span(), 1000));

    // Both keys must be non-zero
    bool encAllZero = true;
    bool macAllZero = true;
    for (size_t i = 0; i < 32; ++i) {
        if (encKey[i] != 0) encAllZero = false;
        if (macKey[i] != 0) macAllZero = false;
    }
    EXPECT_FALSE(encAllZero);
    EXPECT_FALSE(macAllZero);

    // K_enc and K_mac MUST be distinct (dual key separation)
    EXPECT_NE(std::memcmp(encKey.data(), macKey.data(), 32), 0);
}

TEST(KeyDerivationTest, StreamingHmacEquivalence) {
    std::array<uint8_t, 32> key = {0x42};
    std::vector<uint8_t> payload(10000);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(i & 0xFF);
    }

    std::array<uint8_t, 32> singleHmac{};
    ASSERT_TRUE(KeyDerivation::computeHmacSha256(key, payload, singleHmac));

    HmacContext streamingCtx;
    ASSERT_TRUE(streamingCtx.init(key));
    size_t offset = 0;
    size_t chunkSize = 1024;
    while (offset < payload.size()) {
        size_t count = std::min(chunkSize, payload.size() - offset);
        ASSERT_TRUE(streamingCtx.update(payload.data() + offset, count));
        offset += count;
    }

    std::array<uint8_t, 32> streamingHmac{};
    ASSERT_TRUE(streamingCtx.finalize(streamingHmac));

    EXPECT_EQ(singleHmac, streamingHmac);
}

TEST_F(VaultIntegrationTest, PruneStaleLocksRemovesAbandonedLocks) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    auto locksDir = m_vaultDir / "locks";
    auto staleLockPath = locksDir / "abandoned_job.lock";
    {
        std::ofstream f(staleLockPath);
        f << "stale";
    }
    ASSERT_TRUE(std::filesystem::exists(staleLockPath));

    EXPECT_EQ(vault.pruneStaleLocks(), 1U);
    EXPECT_FALSE(std::filesystem::exists(staleLockPath));
}

TEST_F(VaultIntegrationTest, RejectSymlinkAttack) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    auto realFile = createDummyFile("real.txt", 128);
    auto symlinkPath = m_scratchDir / "symlink.txt";

    std::error_code ec;
    std::filesystem::create_symlink(realFile, symlinkPath, ec);
    if (!ec) {
        EXPECT_FALSE(vault.encryptFile(symlinkPath, "TestPassphrase123"));
    }
}

TEST_F(VaultIntegrationTest, RejectPathTraversal) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    auto dest = m_scratchDir / "out.txt";
    EXPECT_FALSE(vault.decryptFile("../../../etc/shadow", dest, "TestPassphrase123"));
    EXPECT_FALSE(vault.decryptFile("subdir/secret", dest, "TestPassphrase123"));
    EXPECT_FALSE(vault.decryptFile("..", dest, "TestPassphrase123"));
    EXPECT_FALSE(vault.decryptFile("", dest, "TestPassphrase123"));
}

TEST_F(VaultIntegrationTest, PosixMetadataPreservation) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "script.sh";
    auto sourcePath = createDummyFile(testFilename, 512);

    // Set executable permissions 0755 and specific mtime
    mode_t targetMode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH; // 0755
    ASSERT_EQ(::chmod(sourcePath.c_str(), targetMode), 0);

    struct timespec customTimes[2];
    customTimes[0].tv_sec = 1700000000; // atime
    customTimes[0].tv_nsec = 0;
    customTimes[1].tv_sec = 1700000000; // mtime
    customTimes[1].tv_nsec = 0;
    ASSERT_EQ(::utimensat(AT_FDCWD, sourcePath.c_str(), customTimes, 0), 0);

    std::string passphrase = "PosixMetadataPassphrase#1";
    ASSERT_TRUE(vault.encryptFile(sourcePath, passphrase));

    auto restoredPath = m_scratchDir / "script_restored.sh";
    ASSERT_TRUE(vault.decryptFile(testFilename, restoredPath, passphrase));

    struct stat restStat{};
    ASSERT_EQ(::stat(restoredPath.c_str(), &restStat), 0);

    // Verify mode bits match (including executable bits)
    EXPECT_EQ(restStat.st_mode & 07777, targetMode);
    // Verify mtime restored
    EXPECT_EQ(restStat.st_mtime, 1700000000);
}

TEST_F(VaultIntegrationTest, ListRecordsInventory) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    auto fileA = createDummyFile("doc_a.txt", 100);
    auto fileB = createDummyFile("doc_b.pdf", 2000);
    std::string pass = "InventoryTestPass#1";

    ASSERT_TRUE(vault.encryptFile(fileA, pass));
    ASSERT_TRUE(vault.encryptFile(fileB, pass));

    auto records = vault.listRecords();
    ASSERT_EQ(records.size(), 2U);

    EXPECT_EQ(records[0].filename, "doc_a.txt");
    EXPECT_EQ(records[0].original_size, 100U);
    EXPECT_EQ(records[0].version, 3U);
    EXPECT_FALSE(records[0].is_locked);

    EXPECT_EQ(records[1].filename, "doc_b.pdf");
    EXPECT_EQ(records[1].original_size, 2000U);
    EXPECT_EQ(records[1].version, 3U);
    EXPECT_FALSE(records[1].is_locked);
}

TEST_F(VaultIntegrationTest, InPlaceCryptographicVerification) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "audit_target.bin";
    auto sourcePath = createDummyFile(testFilename, 1024);
    std::string pass = "CryptographicAuditPass#1";

    ASSERT_TRUE(vault.encryptFile(sourcePath, pass));

    // Verify with correct passphrase without disk extraction
    EXPECT_TRUE(vault.verifyRecord(testFilename, pass));

    // Reject wrong passphrase
    EXPECT_FALSE(vault.verifyRecord(testFilename, "WrongPassphrase123"));

    // Tamper with record on disk and ensure verify catches it
    auto recordPath = m_vaultDir / "records" / (testFilename + ".enc");
    {
        std::fstream f(recordPath, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(f.is_open());
        f.seekp(100); // within payload
        char byte = 0;
        f.read(&byte, 1);
        byte = static_cast<char>(byte ^ 0x55); // flip bits
        f.seekp(100);
        f.write(&byte, 1);
    }

    EXPECT_FALSE(vault.verifyRecord(testFilename, pass));
}

TEST_F(VaultIntegrationTest, SafeRecordDeletion) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    std::string testFilename = "to_delete.txt";
    auto sourcePath = createDummyFile(testFilename, 512);
    ASSERT_TRUE(vault.encryptFile(sourcePath, "DeletePass#1"));

    EXPECT_EQ(vault.listRecords().size(), 1U);
    EXPECT_TRUE(vault.deleteRecord(testFilename));

    // After deletion, listRecords is empty
    EXPECT_EQ(vault.listRecords().size(), 0U);

    // Deleting again fails
    EXPECT_FALSE(vault.deleteRecord(testFilename));
}

TEST_F(VaultIntegrationTest, SecureFileShredding) {
    auto sensitiveFile = createDummyFile("sensitive_financials.csv", 4096);
    ASSERT_TRUE(std::filesystem::exists(sensitiveFile));

    EXPECT_TRUE(VaultManager::shredFile(sensitiveFile));
    EXPECT_FALSE(std::filesystem::exists(sensitiveFile));
}

TEST_F(VaultIntegrationTest, DirectoryArchivingRoundTrip) {
    VaultManager vault(m_vaultDir);
    ASSERT_TRUE(vault.initializeVault());

    // Create a directory tree
    auto treeRoot = m_scratchDir / "my_project";
    auto subDir = treeRoot / "subdir";
    std::filesystem::create_directories(subDir);

    auto f1 = treeRoot / "readme.txt";
    {
        std::ofstream ofs(f1);
        ofs << "Hello from root!";
    }

    auto f2 = subDir / "run.sh";
    {
        std::ofstream ofs(f2);
        ofs << "#!/bin/sh\necho running\n";
    }
    ::chmod(f2.c_str(), 0755);

    std::string pass = "DirArchivePass#1";
    ASSERT_TRUE(vault.encryptDirectory(treeRoot, pass, "my_project"));

    auto restoredDir = m_scratchDir / "restored_project";
    ASSERT_TRUE(vault.decryptDirectory("my_project.kvdir", restoredDir, pass));

    // Verify directory structure restored
    EXPECT_TRUE(std::filesystem::exists(restoredDir / "readme.txt"));
    EXPECT_TRUE(std::filesystem::exists(restoredDir / "subdir" / "run.sh"));

    struct stat runStat{};
    ASSERT_EQ(::stat((restoredDir / "subdir" / "run.sh").c_str(), &runStat), 0);
    EXPECT_EQ(runStat.st_mode & 07777, 0755U);

    std::ifstream origFile(f1);
    std::ifstream restFile(restoredDir / "readme.txt");
    std::string origContent((std::istreambuf_iterator<char>(origFile)), {});
    std::string restContent((std::istreambuf_iterator<char>(restFile)), {});
    EXPECT_EQ(origContent, restContent);
}

