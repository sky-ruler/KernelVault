/**
 * @file test_unique_fd.cpp
 * @brief Google Test suite for C++20 UniqueFd RAII wrapper in kvault.
 */

#include "UniqueFd.hpp"
#include <gtest/gtest.h>

#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

using namespace kvault;

TEST(UniqueFdTest, DefaultConstructorIsInvalid) {
    UniqueFd ufd;
    EXPECT_EQ(ufd.get(), -1);
    EXPECT_FALSE(ufd.valid());
    EXPECT_FALSE(static_cast<bool>(ufd));
}

TEST(UniqueFdTest, ConstructorAdoptsDescriptor) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    UniqueFd readFd(fds[0]);
    UniqueFd writeFd(fds[1]);

    EXPECT_TRUE(readFd.valid());
    EXPECT_TRUE(writeFd.valid());
    EXPECT_EQ(readFd.get(), fds[0]);
    EXPECT_EQ(writeFd.get(), fds[1]);
}

TEST(UniqueFdTest, DestructorClosesDescriptor) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    int rawRead = fds[0];

    {
        UniqueFd scopedFd(rawRead);
        EXPECT_TRUE(scopedFd.valid());
    } // scopedFd destroyed here

    // ::close should now fail with EBADF since UniqueFd already closed it
    EXPECT_EQ(::close(rawRead), -1);
    EXPECT_EQ(errno, EBADF);

    ::close(fds[1]);
}

TEST(UniqueFdTest, MoveSemanticsTransferOwnership) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    UniqueFd ufd1(fds[0]);
    int raw = ufd1.get();

    UniqueFd ufd2(std::move(ufd1));
    EXPECT_FALSE(ufd1.valid());
    EXPECT_EQ(ufd1.get(), -1);
    EXPECT_TRUE(ufd2.valid());
    EXPECT_EQ(ufd2.get(), raw);

    UniqueFd ufd3;
    ufd3 = std::move(ufd2);
    EXPECT_FALSE(ufd2.valid());
    EXPECT_TRUE(ufd3.valid());
    EXPECT_EQ(ufd3.get(), raw);

    ::close(fds[1]);
}

TEST(UniqueFdTest, ReleaseRelinquishesOwnership) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    int rawRead = fds[0];
    {
        UniqueFd ufd(rawRead);
        int released = ufd.release();
        EXPECT_EQ(released, rawRead);
        EXPECT_FALSE(ufd.valid());
    } // Destruction should NOT close released descriptor

    // Closing rawRead should succeed
    EXPECT_EQ(::close(rawRead), 0);
    ::close(fds[1]);
}
