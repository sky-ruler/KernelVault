/**
 * @file UniqueFd.cpp
 * @brief Implementation of C++20 move-only RAII File Descriptor wrapper.
 */

#include "UniqueFd.hpp"

#include <unistd.h>

namespace kvault {

UniqueFd::UniqueFd(int fd) noexcept : m_fd(fd) {}

UniqueFd::~UniqueFd() noexcept {
    reset(-1);
}

UniqueFd::UniqueFd(UniqueFd&& other) noexcept : m_fd(other.release()) {}

UniqueFd& UniqueFd::operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
        reset(other.release());
    }
    return *this;
}

int UniqueFd::get() const noexcept {
    return m_fd;
}

bool UniqueFd::valid() const noexcept {
    return m_fd >= 0;
}

UniqueFd::operator bool() const noexcept {
    return valid();
}

int UniqueFd::release() noexcept {
    int old_fd = m_fd;
    m_fd = -1;
    return old_fd;
}

void UniqueFd::reset(int new_fd) noexcept {
    if (m_fd >= 0) {
        ::close(m_fd);
    }
    m_fd = new_fd;
}

} // namespace kvault
