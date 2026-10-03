/**
 * @file FileLock.cpp
 * @brief Implementation of POSIX fcntl advisory file locking for kvault.
 */

#include "FileLock.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace kvault {

FileLock::FileLock(int fd, LockType type, LockMode mode) {
    acquire(fd, type, mode);
}

FileLock::~FileLock() noexcept {
    unlock();
}

FileLock::FileLock(FileLock&& other) noexcept
    : m_fd(other.m_fd),
      m_locked(other.m_locked),
      m_type(other.m_type) {
    other.m_fd = -1;
    other.m_locked = false;
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
    if (this != &other) {
        unlock();
        m_fd = other.m_fd;
        m_locked = other.m_locked;
        m_type = other.m_type;

        other.m_fd = -1;
        other.m_locked = false;
    }
    return *this;
}

bool FileLock::acquire(int fd, LockType type, LockMode mode) {
    if (fd < 0) {
        return false;
    }

    if (m_locked) {
        unlock();
    }

    struct flock fl{};
    fl.l_type = (type == LockType::Shared) ? F_RDLCK : F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; /* 0 indicates lock covers entire file to EOF */

    int cmd = (mode == LockMode::Blocking) ? F_SETLKW : F_SETLK;
    int res = ::fcntl(fd, cmd, &fl);
    if (res == 0) {
        m_fd = fd;
        m_locked = true;
        m_type = type;
        return true;
    }
    return false;
}

bool FileLock::unlock() noexcept {
    if (!m_locked || m_fd < 0) {
        return false;
    }

    struct flock fl{};
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    int res = ::fcntl(m_fd, F_SETLK, &fl);
    m_locked = false;
    m_fd = -1;
    return (res == 0);
}

bool FileLock::isLocked() const noexcept {
    return m_locked;
}

FileLock::LockType FileLock::getType() const noexcept {
    return m_type;
}

std::optional<pid_t> FileLock::testLock(int fd, LockType type) {
    if (fd < 0) {
        return std::nullopt;
    }

    struct flock fl{};
    fl.l_type = (type == LockType::Shared) ? F_RDLCK : F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (::fcntl(fd, F_GETLK, &fl) == 0) {
        if (fl.l_type != F_UNLCK) {
            return fl.l_pid;
        }
    }
    return std::nullopt;
}

} // namespace kvault
