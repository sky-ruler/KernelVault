## Description
<!-- Provide a concise description of the changes introduced by this pull request. -->

Closes #<!-- issue number if applicable -->

## Subsystem(s) Modified
- [ ] Core Crypto Engine (`src/KeyDerivation.cpp`, `include/PinnedMemory.hpp`)
- [ ] Vault Orchestrator (`src/VaultManager.cpp`, `include/VaultManager.hpp`)
- [ ] Linux Character Driver (`driver/kvault_module.c`)
- [ ] Desktop GUI (`src/gui_main.cpp`)
- [ ] CLI Interface (`src/main.cpp`)
- [ ] Documentation / Runbooks (`docs/`, `README.md`)
- [ ] CI/CD & Build Configuration (`.github/`, `CMakeLists.txt`)

## Architectural & Security Invariants Checklist
- [ ] **Header Size Invariant:** `static_assert(sizeof(VaultHeader) == 96)` holds and was not altered.
- [ ] **Zero Compiler Warnings:** Code compiles cleanly with `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion`.
- [ ] **Memory Hygiene:** Sensitive buffers use `PinnedMemory<N>` or are scrubbed with `KeyDerivation::secureZero()` / `memzero_explicit()`. No plain allocations for keys.
- [ ] **Automated Tests:** All existing unit tests pass, and new tests were added covering new functionality (`ctest --test-dir build`).
- [ ] **Sanitizer Pass:** All tests pass cleanly under **AddressSanitizer (ASan)** and **UndefinedBehaviorSanitizer (UBSan)** without memory leaks or UB.
- [ ] **Kernel Boundary Safety:** No uncontrolled user pointers dereferenced in kernel space; all inputs validated with `copy_from_user` / `copy_to_user`.
- [ ] **Documentation:** `README.md`, `RUNBOOK.md`, or `ARCHITECTURE.md` updated to reflect any behavioral or CLI flag changes.

## Verification & Testing Performed
<!-- Describe the specific tests, commands, or benchmarks executed to verify these changes. -->
```bash
# Example verification command:
ctest --test-dir build --output-on-failure
```
