/**
 * @file AtomicFileWriter.cpp
 * @brief Implementation of transactional atomic file persistence for kvault.
 */

#include "AtomicFileWriter.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

#include <chrono>
#include <random>
#include <system_error>
#include <cerrno>

namespace kvault {

namespace {

int callRenameat2(const char* oldpath, const char* newpath, unsigned int flags) {
    return static_cast<int>(::syscall(SYS_renameat2, AT_FDCWD, oldpath, AT_FDCWD, newpath, flags));
}

} // namespace

AtomicFileWriter::AtomicFileWriter(std::filesystem::path destinationPath, bool overwrite)
    : m_destPath(std::move(destinationPath)),
      m_overwrite(overwrite) {
    auto parent = m_destPath.parent_path();
    if (parent.empty()) {
        parent = std::filesystem::current_path();
    }

    // Generate unique temporary path in same directory
    const auto pid = getpid();
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    const uint64_t random_val = dist(gen);

    std::string tempFilename = "." + m_destPath.filename().string() +
                               ".tmp." + std::to_string(pid) +
                               "." + std::to_string(now) +
                               "." + std::to_string(random_val);

    m_tempPath = parent / tempFilename;
}

AtomicFileWriter::~AtomicFileWriter() noexcept {
    if (!m_committed) {
        abort();
    }
}

AtomicFileWriter::AtomicFileWriter(AtomicFileWriter&& other) noexcept
    : m_destPath(std::move(other.m_destPath)),
      m_tempPath(std::move(other.m_tempPath)),
      m_tempFd(std::move(other.m_tempFd)),
      m_committed(other.m_committed),
      m_overwrite(other.m_overwrite) {
    other.m_committed = true; // Prevents abort on moved-from instance
}

AtomicFileWriter& AtomicFileWriter::operator=(AtomicFileWriter&& other) noexcept {
    if (this != &other) {
        if (!m_committed) {
            abort();
        }
        m_destPath = std::move(other.m_destPath);
        m_tempPath = std::move(other.m_tempPath);
        m_tempFd = std::move(other.m_tempFd);
        m_committed = other.m_committed;
        m_overwrite = other.m_overwrite;

        other.m_committed = true;
    }
    return *this;
}

bool AtomicFileWriter::open() {
    if (m_tempFd.valid()) {
        return true;
    }

    // Ensure parent directory exists
    const auto parent = m_tempPath.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::error_code ec;
        if (!std::filesystem::create_directories(parent, ec) && ec) {
            return false;
        }
    }

    // Strictly enforce 0600 (S_IRUSR | S_IWUSR) permissions and defend against symlink hijacking
    int fd = ::open(m_tempPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR);

    if (fd < 0) {
        return false;
    }

    m_tempFd.reset(fd);
    m_committed = false;
    return true;
}

bool AtomicFileWriter::write(std::span<const uint8_t> buffer) {
    if (!m_tempFd.valid()) {
        if (!open()) {
            return false;
        }
    }

    const uint8_t* ptr = buffer.data();
    size_t remaining = buffer.size();

    while (remaining > 0) {
        ssize_t written = ::write(m_tempFd.get(), ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            return false;
        }
        ptr += written;
        remaining -= static_cast<size_t>(written);
    }

    return true;
}

bool AtomicFileWriter::commit() {
    if (!m_tempFd.valid()) {
        return false;
    }

    // 1. Flush volatile drive cache & write dirty pages to storage hardware
    if (::fsync(m_tempFd.get()) != 0) {
        abort();
        return false;
    }

    // 2. Close temporary file descriptor before renaming
    m_tempFd.reset(-1);

    // 3. Atomically rename temporary file to destination path
    unsigned int flags = m_overwrite ? 0 : RENAME_NOREPLACE;
    int res = callRenameat2(m_tempPath.string().c_str(), m_destPath.string().c_str(), flags);

    if (res != 0) {
        if (errno == EXDEV) {
            // Cross-filesystem move fallback: copy, fsync destination, remove temp
            std::error_code copyEc;
            std::filesystem::copy_file(m_tempPath, m_destPath,
                m_overwrite ? std::filesystem::copy_options::overwrite_existing
                            : std::filesystem::copy_options::none, copyEc);
            if (copyEc) {
                abort();
                return false;
            }
            std::filesystem::remove(m_tempPath, copyEc);
        } else if ((errno == ENOSYS || errno == EINVAL) && m_overwrite) {
            // Fallback to std::filesystem::rename if renameat2 returned ENOSYS or EINVAL
            std::error_code ec;
            std::filesystem::rename(m_tempPath, m_destPath, ec);
            if (ec) {
                if (ec.value() == EXDEV) {
                    std::filesystem::copy_file(m_tempPath, m_destPath,
                        std::filesystem::copy_options::overwrite_existing, ec);
                    if (ec) {
                        abort();
                        return false;
                    }
                    std::filesystem::remove(m_tempPath, ec);
                } else {
                    abort();
                    return false;
                }
            }
        } else {
            abort();
            return false;
        }
    }

    // 4. Flush parent directory metadata so rename persists across crashes
    m_committed = true;
    return syncParentDirectory();
}

void AtomicFileWriter::abort() noexcept {
    m_tempFd.reset(-1);

    if (!m_tempPath.empty()) {
        std::error_code ec;
        std::filesystem::remove(m_tempPath, ec);
    }

    m_committed = true;
}

const std::filesystem::path& AtomicFileWriter::getTempPath() const noexcept {
    return m_tempPath;
}

const std::filesystem::path& AtomicFileWriter::getDestinationPath() const noexcept {
    return m_destPath;
}

bool AtomicFileWriter::syncParentDirectory() const {
    auto parent = m_destPath.parent_path();
    if (parent.empty()) {
        parent = ".";
    }

    int dir_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        const bool synced = (::fsync(dir_fd) == 0);
        ::close(dir_fd);
        return synced;
    }
    return false;
}

} // namespace kvault
