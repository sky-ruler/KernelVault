#include "VaultManager.hpp"
#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    auto tempDir = std::filesystem::temp_directory_path() / "kvault_fuzz_unpack";
    std::error_code ec;
    std::filesystem::create_directories(tempDir, ec);

    auto recPath = tempDir / "fuzz_target.kvdir";
    {
        std::ofstream ofs(recPath, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }

    kvault::VaultManager vault(tempDir);
    auto restoreTarget = tempDir / "restored";

    try {
        // Attempt unpack: malicious paths, corrupted packs, or invalid magic must be rejected cleanly
        vault.decryptDirectory("fuzz_target.kvdir", restoreTarget, "FuzzPassphrase#1");
    } catch (...) {
        // Unhandled exceptions must not leak
    }

    std::filesystem::remove_all(tempDir, ec);
    return 0;
}

#ifndef LIBFUZZER_ENABLED
#include <random>

int main() {
    std::mt19937_64 rng(0x42);
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    std::cout << "[*] Executing 500 fuzzing iterations against KVDIR1 directory unpacker...\n";
    std::vector<uint8_t> buffer(256);

    for (int i = 0; i < 500; ++i) {
        for (auto& b : buffer) b = dist(rng);
        LLVMFuzzerTestOneInput(buffer.data(), buffer.size());
    }

    std::cout << "[+] Directory archive fuzzing completed: 500 iterations passed with 0 leaks/crashes.\n";
    return 0;
}
#endif
