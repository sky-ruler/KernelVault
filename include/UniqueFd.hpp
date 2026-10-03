/**
 * @file UniqueFd.hpp
 * @brief C++20 move-only RAII File Descriptor wrapper for POSIX resources.
 *
 * Enforces deterministic resource management (RAII) over Linux file descriptors,
 * guaranteeing close() is invoked on scope exit, exception, or destruction.
 */

#ifndef UNIQUE_FD_HPP
#define UNIQUE_FD_HPP

#include <utility>

namespace kvault {

/**
 * @class UniqueFd
 * @brief Move-only RAII wrapper for POSIX integer file descriptors.
 *
 * Guarantees exception-safe lifetime management for file descriptors.
 * Explicitly disables copy construction and copy assignment.
 */
class UniqueFd {
public:
    /**
     * @brief Constructs a UniqueFd wrapping an optional file descriptor.
     * @param fd Raw POSIX file descriptor (defaults to -1, indicating empty/invalid).
     */
    explicit UniqueFd(int fd = -1) noexcept;

    /**
     * @brief Destructor. Closes the underlying file descriptor if valid.
     */
    ~UniqueFd() noexcept;

    // Move-only semantics: copy construction and assignment deleted
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    /**
     * @brief Move constructor. Transfers ownership of the descriptor.
     * @param other Rvalue reference to source UniqueFd.
     */
    UniqueFd(UniqueFd&& other) noexcept;

    /**
     * @brief Move assignment operator. Closes existing fd and adopts other's fd.
     * @param other Rvalue reference to source UniqueFd.
     * @return Reference to this object.
     */
    UniqueFd& operator=(UniqueFd&& other) noexcept;

    /**
     * @brief Access the raw integer file descriptor.
     * @return The underlying file descriptor or -1.
     */
    [[nodiscard]] int get() const noexcept;

    /**
     * @brief Checks if the managed descriptor is valid (>= 0).
     * @return True if valid, false otherwise.
     */
    [[nodiscard]] bool valid() const noexcept;

    /**
     * @brief Contextual boolean conversion operator.
     * @return True if descriptor is valid, false otherwise.
     */
    explicit operator bool() const noexcept;

    /**
     * @brief Releases ownership of the file descriptor without closing it.
     * @return The raw descriptor value.
     */
    int release() noexcept;

    /**
     * @brief Closes current descriptor (if valid) and adopts a new descriptor.
     * @param new_fd New descriptor to manage (defaults to -1).
     */
    void reset(int new_fd = -1) noexcept;

private:
    int m_fd{-1};
};

} // namespace kvault


#endif // UNIQUE_FD_HPP
