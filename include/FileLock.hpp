/**
 * @file FileLock.hpp
 * @brief POSIX advisory file locking interface utilizing fcntl().
 *
 * Implements deterministic RAII locking semantics supporting shared (read)
 * and exclusive (write) advisory locks across multi-process workloads.
 */

#ifndef FILE_LOCK_HPP
#define FILE_LOCK_HPP

#include <optional>
#include <sys/types.h>

namespace kvault {

/**
 * @class FileLock
 * @brief RAII management class for POSIX fcntl advisory locks.
 */
class FileLock {
public:
    /**
     * @enum LockType
     * @brief Type of lock requested.
     */
    enum class LockType {
        Shared,    /**< F_RDLCK: Multiple concurrent readers allowed */
        Exclusive  /**< F_WRLCK: Single mutating writer, blocks all others */
    };

    /**
     * @enum LockMode
     * @brief Blocking behavior when acquiring lock.
     */
    enum class LockMode {
        Blocking,    /**< F_SETLKW: Suspends process until lock is acquired */
        NonBlocking  /**< F_SETLK: Returns immediately, failing if contested */
    };

    /**
     * @brief Constructs an unlocked FileLock instance.
     */
    FileLock() noexcept = default;

    /**
     * @brief Acquires advisory lock on target file descriptor.
     * @param fd Open file descriptor to lock.
     * @param type LockType::Shared or LockType::Exclusive.
     * @param mode LockMode::Blocking or LockMode::NonBlocking.
     */
    FileLock(int fd, LockType type, LockMode mode);

    /**
     * @brief Destructor. Automatically unlocks the file descriptor if locked.
     */
    ~FileLock() noexcept;

    // Move-only semantics
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    FileLock(FileLock&& other) noexcept;
    FileLock& operator=(FileLock&& other) noexcept;

    /**
     * @brief Explicitly attempts to acquire a lock.
     * @param fd Target file descriptor.
     * @param type Lock type.
     * @param mode Acquisition mode.
     * @return True if acquired, false otherwise.
     */
    bool acquire(int fd, LockType type, LockMode mode);

    /**
     * @brief Releases the acquired lock.
     * @return True on successful unlock, false otherwise.
     */
    bool unlock() noexcept;

    /**
     * @brief Checks if lock is currently held by this instance.
     */
    [[nodiscard]] bool isLocked() const noexcept;

    /**
     * @brief Gets current lock type held.
     */
    [[nodiscard]] LockType getType() const noexcept;

    /**
     * @brief Tests if another process holds an incompatible lock on the descriptor.
     * @param fd Open file descriptor.
     * @param type Desired lock type to test against.
     * @return Optional holding the PID of blocking process, or std::nullopt if unblocked.
     */
    static std::optional<pid_t> testLock(int fd, LockType type);

private:
    int m_fd{-1};
    bool m_locked{false};
    LockType m_type{LockType::Exclusive};
};

} // namespace kvault


#endif // FILE_LOCK_HPP
