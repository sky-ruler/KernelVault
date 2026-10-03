# Build and Test Guide

This document lists the checks available in the repository and their scope. It is a procedure, not a pass report; results should be recorded only after running them on the named environment. Use a Linux filesystem for both the checkout and build directory. In WSL, clone under `$HOME` rather than `/mnt/c` to avoid CMake file-generation permission errors.

## C++ build and unit/integration suite

Install the prerequisites on Debian or Ubuntu, then configure, build, and run CTest from the repository root:

```bash
sudo apt update
sudo apt install -y build-essential cmake libgtest-dev qt6-base-dev
```

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_GUI=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

GoogleTest is resolved from the system package. CMake falls back to FetchContent when GoogleTest is unavailable, which requires network access.

The current GoogleTest suite contains **31 automated test cases** across 5 test suites:

- **`UniqueFd` (5 tests):** Descriptor ownership, move semantics, close on destruction, and release behavior.
- **`FileLock` (4 tests):** Shared and exclusive POSIX `fcntl` record locking, destructor release, and move semantics.
- **`AtomicFileWriter` (4 tests):** Commit creation, abort cleanup, uncommitted destructor abort, overwrite replacing, and file permissions.
- **`KeyDerivationTest` (3 tests):**
  - `PinnedMemoryLifecycleAndZeroing`: Verifies physical `mlock` allocation, memory protection, and compiler-barrier zeroization.
  - `DualKeyDerivationIndependence`: Cryptographically verifies $K_{\text{enc}} \neq K_{\text{mac}}$ across RFC 2898 multi-block PBKDF2.
  - `StreamingHmacEquivalence`: Verifies that bounded 64 KiB chunk updates in `HmacContext` match monolithic HMAC-SHA256 calculations bit-for-bit.
- **`VaultIntegrationTest` (15 tests):**
  - `VaultInitializationLifecycle`: Directory structure and metadata initialization idempotency.
  - `EncryptDecryptRoundTripSmallFile`: Single-chunk round-trip data fidelity.
  - `EncryptDecryptMultiChunkLargeFile`: Multi-chunk streaming round-trip with PKCS#7 boundary padding across 64 KiB chunk blocks.
  - `RejectIncorrectPassphrase`: Authentication rejection on wrong credentials.
  - `RejectTamperedCiphertext`: Authentication rejection on single-bit ciphertext modification.
  - `RejectTamperedHeader`: Authentication rejection on header field modification.
  - `PruneStaleLocksRemovesAbandonedLocks`: Garbage collection of abandoned lock files.
  - `RejectSymlinkAttack`: Symlink resolution defense (`O_NOFOLLOW`).
  - `RejectPathTraversal`: Relative path traversal defense (`..` rejection).
  - `PosixMetadataPreservation`: Verifies that restored executable scripts retain `0755` permissions and `utimensat` modification timestamps.
  - `ListRecordsInventory`: Verifies tabular inventory retrieval, record sizes, formats, and non-blocking lock detection.
  - `InPlaceCryptographicVerification`: Verifies zero-footprint streaming HMAC validation without disk extraction.
  - `SafeRecordDeletion`: Verifies advisory mutex protection during record deletion and lockfile unlinking.
  - `SecureFileShredding`: Verifies multi-pass CSPRNG overwriting, zeroization, and unlinking.
  - `DirectoryArchivingRoundTrip`: Verifies recursive directory tree archiving, nested subdirectories, permissions, and safe extraction.

The tests run only on Linux because they exercise POSIX descriptors, locks, and file permissions.

The GUI is included in the C++ build when `BUILD_GUI=ON`. Automated tests cover the shared vault engine; there is no automated Qt window-interaction test. To build just the CLI/test suite on a machine without Qt, omit `qt6-base-dev` and configure with `-DBUILD_GUI=OFF`.

## Sanitizers

Configure an AddressSanitizer/UndefinedBehaviorSanitizer build with:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DENABLE_ASAN=ON
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

## Kernel module build

Build the out-of-tree module against the running kernel's headers:

```bash
make -C driver
modinfo driver/kvault.ko
```

To target another installed kernel build directory, pass `KDIR=/path/to/kernel/build`.

## Manual driver exercise

Module compilation needs kernel headers for the target kernel. Module loading requires a suitable Linux kernel and root privileges. WSL may not provide the matching headers or permit this module to load; use a disposable Linux VM:

```bash
sudo insmod driver/kvault.ko
ls -l /dev/kvault
./build/kvault status --vault /tmp/kvault-test
sudo dmesg | tail -n 30
sudo rmmod kvault
```

Exercise encryption and decryption with the driver loaded and compare the restored file to its original. Repeat with the module unloaded to exercise the software fallback.

## Automated coverage boundary

GitHub Actions builds the user-space application and runs CTest with GCC and Clang. A separate job builds the kernel module against installed Ubuntu headers. CI does not load the module, test live IOCTL behavior, inspect key memory, or establish security against a real attacker. Those claims require separate controlled Linux testing and should not be inferred from a successful build.
