/**
 * @file PinnedMemory.hpp
 * @brief RAII memory container that locks sensitive pages into RAM via mlock().
 *
 * Prevents operating system swap mechanisms from paging sensitive cryptographic
 * material (passphrases, derived AES and HMAC keys) onto unencrypted physical storage.
 * Enforces secure memory zeroization upon destruction.
 */

#ifndef PINNED_MEMORY_HPP
#define PINNED_MEMORY_HPP

#include <sys/mman.h>
#include <cstddef>
#include <cstdint>
#include <array>
#include <span>
#include <utility>
#include "KeyDerivation.hpp"

namespace kvault {

template <size_t N>
class PinnedMemory {
public:
    PinnedMemory() noexcept {
        m_data.fill(0);
        // Best-effort page lock. If unprivileged or resource limit exceeded, continues safely.
        ::mlock(m_data.data(), N);
    }

    ~PinnedMemory() noexcept {
        KeyDerivation::secureZero(m_data.data(), N);
        ::munlock(m_data.data(), N);
    }

    // Move-only semantics
    PinnedMemory(const PinnedMemory&) = delete;
    PinnedMemory& operator=(const PinnedMemory&) = delete;

    PinnedMemory(PinnedMemory&& other) noexcept {
        m_data = other.m_data;
        ::mlock(m_data.data(), N);
        KeyDerivation::secureZero(other.m_data.data(), N);
        ::munlock(other.m_data.data(), N);
    }

    PinnedMemory& operator=(PinnedMemory&& other) noexcept {
        if (this != &other) {
            KeyDerivation::secureZero(m_data.data(), N);
            ::munlock(m_data.data(), N);
            m_data = other.m_data;
            ::mlock(m_data.data(), N);
            KeyDerivation::secureZero(other.m_data.data(), N);
            ::munlock(other.m_data.data(), N);
        }
        return *this;
    }

    [[nodiscard]] uint8_t* data() noexcept { return m_data.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return m_data.data(); }
    [[nodiscard]] constexpr size_t size() const noexcept { return N; }

    [[nodiscard]] std::span<uint8_t, N> span() noexcept {
        return std::span<uint8_t, N>(m_data.data(), N);
    }

    [[nodiscard]] std::span<const uint8_t, N> span() const noexcept {
        return std::span<const uint8_t, N>(m_data.data(), N);
    }

    uint8_t& operator[](size_t index) noexcept { return m_data[index]; }
    const uint8_t& operator[](size_t index) const noexcept { return m_data[index]; }

private:
    std::array<uint8_t, N> m_data{};
};

} // namespace kvault

#endif // PINNED_MEMORY_HPP
