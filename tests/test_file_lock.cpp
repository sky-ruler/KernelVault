/**
 * @file test_file_lock.cpp
 * @brief Google Test suite for POSIX fcntl advisory locking abstraction in kvault.
 */

#include "FileLock.hpp"
#include "UniqueFd.hpp"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include <fcntl.h>
#include <unistd.h>

using namespace kvault;

class FileLockTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_testFile = std::filesystem::temp_directory_path() / "kvault_test_lock.dat";
        std::ofstream ofs(m_testFile);
        ofs << "test lock data payload\n";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove(m_testFile, ec);
    }

    std::filesystem::path m_testFile;
};

TEST_F(FileLockTest, AcquireExclusiveLockSuccess) {
    int fd = ::open(m_testFile.c_str(), O_RDWR);
    ASSERT_GE(fd, 0);
    UniqueFd ufd(fd);

    FileLock lock(ufd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
    EXPECT_TRUE(lock.isLocked());
    EXPECT_EQ(lock.getType(), FileLock::LockType::Exclusive);

    EXPECT_TRUE(lock.unlock());
    EXPECT_FALSE(lock.isLocked());
}

TEST_F(FileLockTest, AcquireSharedLockSuccess) {
    int fd = ::open(m_testFile.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    UniqueFd ufd(fd);

    FileLock lock(ufd.get(), FileLock::LockType::Shared, FileLock::LockMode::NonBlocking);
    EXPECT_TRUE(lock.isLocked());
    EXPECT_EQ(lock.getType(), FileLock::LockType::Shared);

    EXPECT_TRUE(lock.unlock());
    EXPECT_FALSE(lock.isLocked());
}

TEST_F(FileLockTest, DestructorReleasesLock) {
    int fd = ::open(m_testFile.c_str(), O_RDWR);
    ASSERT_GE(fd, 0);
    UniqueFd ufd(fd);

    {
        FileLock lock(ufd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
        EXPECT_TRUE(lock.isLocked());
    } // lock unlocked here

    // Re-acquiring should succeed without issue
    FileLock lock2(ufd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
    EXPECT_TRUE(lock2.isLocked());
}

TEST_F(FileLockTest, MoveSemanticsTransferLockState) {
    int fd = ::open(m_testFile.c_str(), O_RDWR);
    ASSERT_GE(fd, 0);
    UniqueFd ufd(fd);

    FileLock lock1(ufd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
    EXPECT_TRUE(lock1.isLocked());

    FileLock lock2(std::move(lock1));
    EXPECT_FALSE(lock1.isLocked());
    EXPECT_TRUE(lock2.isLocked());
}
