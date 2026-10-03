# Contributing to KernelVault

Thank you for your interest in contributing to **KernelVault**! KernelVault is an enterprise-grade Linux kernel-assisted secure storage subsystem. Because this project manages sensitive user cryptographic material and interacts directly with the Linux kernel boundary, we maintain rigorous engineering standards.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand our community expectations.

---

## Development Standards & Invariants

Every contribution must satisfy the following non-negotiable architectural requirements:

### 1. Zero Compiler Warnings Barrier
All C++ and C code must compile cleanly with **zero warnings** treated as fatal errors:
```bash
-Wall -Wextra -Wpedantic -Werror -Wshadow -Wnon-virtual-dtor \
-Wcast-align -Wunused -Woverloaded-virtual -Wconversion \
-Wsign-conversion -Wnull-dereference -Wdouble-promotion -Wformat=2
```

### 2. Header Size Invariant
The on-disk `VaultHeader` must remain exactly 96 bytes on all platforms and compiler versions:
```cpp
static_assert(sizeof(VaultHeader) == 96, "VaultHeader must be exactly 96 bytes");
```

### 3. Memory Hygiene & Zeroization
- Key material and sensitive passphrases must **never** be copied into standard unbound `std::string` or `std::vector` without zeroization.
- Sensitive buffers must use `PinnedMemory<N>` (backed by `mlock(2)`) or `KeyDerivation::secureZero` with compiler memory barriers.
- In-kernel sessions must use `memzero_explicit()`.

### 4. 100% Automated Test Coverage & Sanitizer Cleanliness
- Any bug fix or new feature must be accompanied by GoogleTest unit/integration tests in `tests/`.
- Pull requests must pass all tests under **AddressSanitizer (ASan)**, **LeakSanitizer (LSan)**, and **UndefinedBehaviorSanitizer (UBSan)**.

---

## Getting Started

### Prerequisites
Ensure your development workstation has:
- Linux kernel 6.x or 7.x with headers (`linux-headers-$(uname -r)`)
- GCC 12+ or Clang 15+ (C++20 support)
- CMake 3.20+
- GoogleTest (`libgtest-dev`)
- Qt6 Widgets (`qt6-base-dev`)

### Local Build & Test Workflow

1. **Fork and Clone:**
   ```bash
   git clone https://github.com/<your-username>/KernelVault.git
   cd KernelVault
   ```

2. **Configure and Build:**
   ```bash
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DBUILD_GUI=ON
   cmake --build build --parallel
   ```

3. **Run Test Suite:**
   ```bash
   ctest --test-dir build --output-on-failure
   ```

4. **Run Sanitizer Audit:**
   ```bash
   cmake -S . -B build-asan -DENABLE_ASAN=ON -DBUILD_TESTING=ON
   cmake --build build-asan --parallel
   ctest --test-dir build-asan --output-on-failure
   ```

5. **Driver Build & Verification (Optional with Root):**
   ```bash
   sudo ./scripts/test_driver.sh
   ```

---

## Commit Message Convention

KernelVault adheres to the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short description>

[optional body]

[optional footer(s)]
```

### Allowed Types:
- `feat`: A new feature or capability (e.g. `feat(crypto): add AES-XTS mode support`)
- `fix`: A bug fix (e.g. `fix(driver): correct ioctl copy_to_user bounds check`)
- `docs`: Documentation updates or runbook changes
- `test`: Adding or refactoring unit/integration test suites
- `refactor`: Code changes that neither fix bugs nor add features
- `perf`: Performance improvements or algorithmic optimizations
- `ci`: Changes to GitHub Actions workflows or scripts

---

## Pull Request Lifecycle

1. **Branch Naming:** Create a focused branch from `main`:
   - `feature/directory-encryption`
   - `fix/memory-pinning-limits`
   - `docs/interview-updates`
2. **Commit Hygiene:** Ensure commits are atomic and logically structured.
3. **Open a PR:** Fill out the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md) completely.
4. **CI Checks:** Automated GitHub Actions will build GCC and Clang matrices, run CodeQL security scanning, execute all 32 tests, and audit memory sanitizers.
5. **Review:** Maintainers will review code within 3 business days.
