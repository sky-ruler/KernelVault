/**
 * @file test_atomic_write.cpp
 * @brief Google Test suite for AtomicFileWriter transactional persistence in kvault.
 */

#include "AtomicFileWriter.hpp"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>

#include <sys/stat.h>

using namespace kvault;

class AtomicFileWriterTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_testDir = std::filesystem::temp_directory_path() / "kvault_atomic_test_dir";
        std::filesystem::create_directories(m_testDir);
        m_targetFile = m_testDir / "committed.dat";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
    }

    std::filesystem::path m_testDir;
    std::filesystem::path m_targetFile;
};

TEST_F(AtomicFileWriterTest, CommitCreatesTargetFile) {
    AtomicFileWriter writer(m_targetFile, true);
    ASSERT_TRUE(writer.open());

    std::vector<uint8_t> payload = {'S', 'E', 'C', 'U', 'R', 'E', '_', 'D', 'A', 'T', 'A'};
    ASSERT_TRUE(writer.write(payload));
    ASSERT_TRUE(writer.commit());

    EXPECT_TRUE(std::filesystem::exists(m_targetFile));
    EXPECT_EQ(std::filesystem::file_size(m_targetFile), payload.size());

    // Verify content on disk
    std::ifstream ifs(m_targetFile, std::ios::binary);
    std::vector<uint8_t> readBack(payload.size());
    ifs.read(reinterpret_cast<char*>(readBack.data()),
             static_cast<std::streamsize>(readBack.size()));
    EXPECT_EQ(readBack, payload);

    // Verify 0600 permissions
    struct stat st{};
    ASSERT_EQ(stat(m_targetFile.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, S_IRUSR | S_IWUSR);
}

TEST_F(AtomicFileWriterTest, AbortLeavesNoDestinationFile) {
    AtomicFileWriter writer(m_targetFile, true);
    ASSERT_TRUE(writer.open());

    std::vector<uint8_t> payload = {'T', 'R', 'A', 'N', 'S', 'A', 'C', 'T', 'I', 'O', 'N'};
    ASSERT_TRUE(writer.write(payload));
    auto tempPath = writer.getTempPath();
    EXPECT_TRUE(std::filesystem::exists(tempPath));

    writer.abort();

    EXPECT_FALSE(std::filesystem::exists(m_targetFile));
    EXPECT_FALSE(std::filesystem::exists(tempPath));
}

TEST_F(AtomicFileWriterTest, DestructorAbortsUncommitted) {
    std::filesystem::path tempPath;
    {
        AtomicFileWriter writer(m_targetFile, true);
        ASSERT_TRUE(writer.open());
        std::vector<uint8_t> payload = {'A', 'B', 'O', 'R', 'T'};
        ASSERT_TRUE(writer.write(payload));
        tempPath = writer.getTempPath();
        EXPECT_TRUE(std::filesystem::exists(tempPath));
    } // writer goes out of scope here without commit

    EXPECT_FALSE(std::filesystem::exists(m_targetFile));
    EXPECT_FALSE(std::filesystem::exists(tempPath));
}

TEST_F(AtomicFileWriterTest, OverwriteAtomicallyReplacesFile) {
    // Write original file
    {
        std::ofstream ofs(m_targetFile);
        ofs << "OLD_VERSION_CONTENT";
    }
    ASSERT_TRUE(std::filesystem::exists(m_targetFile));

    // Overwrite atomically
    {
        AtomicFileWriter writer(m_targetFile, true);
        ASSERT_TRUE(writer.open());
        std::vector<uint8_t> newPayload = {'N', 'E', 'W'};
        ASSERT_TRUE(writer.write(newPayload));
        ASSERT_TRUE(writer.commit());
    }

    EXPECT_TRUE(std::filesystem::exists(m_targetFile));
    EXPECT_EQ(std::filesystem::file_size(m_targetFile), 3);

    std::ifstream ifs(m_targetFile);
    std::string content;
    ifs >> content;
    EXPECT_EQ(content, "NEW");
}
