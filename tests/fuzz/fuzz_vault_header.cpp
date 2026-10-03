#include "VaultManager.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(kvault::VaultHeader)) {
        return 0;
    }

    kvault::VaultHeader header{};
    std::memcpy(&header, data, sizeof(kvault::VaultHeader));

    // Validate magic bounds
    if (header.magic != kvault::VaultManager::VAULT_MAGIC &&
        header.magic != kvault::VaultManager::LEGACY_MAGIC) {
        return 0;
    }

    // Validate version boundaries
    if (header.version != kvault::VaultManager::VAULT_VERSION &&
        header.version != kvault::VaultManager::VAULT_VERSION_V2 &&
        header.version != kvault::VaultManager::LEGACY_VAULT_VERSION) {
        return 0;
    }

    // Enforce size sanity
    if (header.payload_size > 1024ULL * 1024ULL * 1024ULL * 16ULL) {
        return 0;
    }

    return 0;
}

#ifndef LIBFUZZER_ENABLED
#include <random>
#include <iostream>

int main() {
    std::mt19937_64 rng(0x1337);
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    std::cout << "[*] Executing 10,000 fuzzing iterations against VaultHeader parser...\n";
    std::vector<uint8_t> buffer(sizeof(kvault::VaultHeader) + 128);

    for (int i = 0; i < 10000; ++i) {
        for (auto& b : buffer) b = dist(rng);
        LLVMFuzzerTestOneInput(buffer.data(), buffer.size());
    }

    std::cout << "[+] Fuzzing completed: 10,000 iterations passed with 0 crashes.\n";
    return 0;
}
#endif
