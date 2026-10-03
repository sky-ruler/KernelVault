# KernelVault

KernelVault is a Linux project that demonstrates a C++20 file-vault application working with a Linux character-device driver written in C. Users can operate the shared vault engine through the command-line interface or an optional native Qt desktop interface. The driver exposes an IOCTL interface to the Linux Kernel Crypto API for AES-256-CBC transformations.

> **Notice:** This project has not received an independent security audit and is not intended to protect production or high-value data.

## Project scope

| Feature | Implementation in this repository |
| --- | --- |
| C/C++ implementation | C++20 vault engine, CLI, and optional Qt GUI in `src/` and `include/`; C Linux driver in `driver/`. |
| Linux operating system | CMake rejects non-Linux builds. The driver uses Linux character-device, IOCTL, and Kernel Crypto API interfaces. |
| Device-driver concepts | Dynamic character-device registration, exclusive open gate, mutex-protected state, `copy_from_user` / `copy_to_user`, IOCTL controls, and key cleanup. |
| Software architecture | CLI and GUI share vault orchestration, key derivation, advisory locking, atomic file writer, and kernel-driver boundary documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). |
| Build and instructions | C/C++ source, build configuration, tests, license, and run instructions are maintained in this repository. |

KernelVault can be operated from a Linux terminal or a native Linux desktop window. Its implementation is C and C++; the optional GUI uses Qt Widgets. There is no browser-based application. CMake, Make/Kbuild, GitHub Actions, and Markdown are build, CI, and documentation artifacts.

## How it works

```mermaid
flowchart LR
    CLI["C++ CLI"] --> VM["VaultManager"]
    GUI["Optional C++ / Qt GUI"] --> VM
    VM --> KDF["PBKDF2-HMAC-SHA256"]
    VM --> LOCK["POSIX fcntl locks"]
    VM --> OUT["Atomic file writer"]
    VM --> DEV{"/dev/kvault available?"}
    DEV -->|Yes| DRIVER["C character driver"]
    DRIVER --> API["Linux Kernel Crypto API\nAES-256-CBC"]
    DEV -->|No| SW["C++ software AES fallback"]
    API --> REC["Authenticated vault record"]
    SW --> REC
    OUT --> REC
```

The driver performs cipher transformations. The C++ application derives keys and authenticates vault records with HMAC-SHA256. The driver is optional: if it is absent or inaccessible, the user-space software cipher fallback is used. The fallback and driver implement the same record-level encryption workflow; records are authenticated before plaintext output is committed. Both the CLI and GUI call the same `VaultManager` implementation.

## Requirements

- Linux (supported project target); Windows users can use Ubuntu on WSL2 for the CLI and WSLg for the GUI
- CMake 3.20 or newer
- GCC 11+ or Clang 14+ with C++20 support
- GNU Make
- GoogleTest to build and run the test suite
- Qt 6.2 or newer (`qt6-base-dev`) to build the optional desktop GUI
- Matching Linux kernel headers only when building the optional driver module

## Quick start (Linux or Ubuntu on WSL2)

On Windows, if WSL2 is not installed yet, run this once from PowerShell as Administrator:

```powershell
wsl --install -d Ubuntu
```

Complete Ubuntu's first-run account setup. Then run the following commands in the **Ubuntu terminal** (not PowerShell). Clone into the Linux home directory. In WSL, building a checkout and build directory under `/mnt/c` can cause CMake `Operation not permitted` errors; keeping the checkout under `$HOME` avoids the Windows-mounted filesystem boundary.

```bash
sudo apt update
sudo apt install -y git build-essential cmake libgtest-dev qt6-base-dev
git clone <repository-url>
cd KernelVault
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_GUI=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/kvault --help
./build/kvault-gui
```

The CLI is `build/kvault`; the desktop app is `build/kvault-gui`. The GUI uses Qt Widgets and shares the same C++ vault engine as the CLI. To build only the CLI and avoid the Qt dependency, omit `qt6-base-dev` and use `-DBUILD_GUI=OFF`. The test suite uses the system GoogleTest installed by `libgtest-dev`; if CMake cannot find it, CMake's FetchContent fallback requires network access.

WSL supports building and running the CLI and, with WSLg, the Qt desktop app. Both use the user-space cipher when `/dev/kvault` is unavailable. Loading and demonstrating the kernel module requires a suitable Linux kernel; use a disposable Ubuntu VM or Linux machine for that part. WSL may not provide matching module headers or permit loading this out-of-tree driver.

### Build from an existing Windows checkout in WSL

If the source is already under `/mnt/c`, keep CMake's build output in WSL's Linux filesystem:

```bash
cmake -S "/mnt/c/Projects/KernelVault" -B "$HOME/kvault-build" \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_GUI=ON
cmake --build "$HOME/kvault-build" --parallel
ctest --test-dir "$HOME/kvault-build" --output-on-failure
"$HOME/kvault-build/kvault" --help
"$HOME/kvault-build/kvault-gui"
```

For a normal Linux checkout, the same configure/build/test commands work with `-S . -B build`.

### Build the optional kernel driver

On a Linux VM or machine with headers for its running kernel, install the driver build tools and matching headers:

```bash
sudo apt install -y kmod linux-headers-$(uname -r)
```

Then build the module separately:

```bash
make -C driver
```

Or use the CMake target:

```bash
cmake --build build --target driver
```

The module build uses the headers for the running kernel by default. To select another installed kernel build tree:

```bash
make -C driver KDIR=/path/to/kernel/build
```

## Run the CLI

The following self-contained round-trip creates temporary input, encrypts it, decrypts it, and stops with an error if the restored file differs:

```bash
set -eu
TEST_DIR="$(mktemp -d /tmp/kvault-test.XXXXXX)"
printf 'KernelVault sample data\n' > "$TEST_DIR/example.txt"
./build/kvault init --vault "$TEST_DIR/vault"
./build/kvault encrypt --vault "$TEST_DIR/vault" --in "$TEST_DIR"/*.txt --key 'sample-passphrase'
./build/kvault list --vault "$TEST_DIR/vault"
./build/kvault verify --vault "$TEST_DIR/vault" --all --key 'sample-passphrase'
./build/kvault decrypt --vault "$TEST_DIR/vault" --all --out-dir "$TEST_DIR/restored" --key 'sample-passphrase'
cmp "$TEST_DIR/example.txt" "$TEST_DIR/restored/example.txt"
echo 'Round trip verified: source and restored files match.'
./build/kvault status --vault "$TEST_DIR/vault"
```

The encrypted record is stored at `$TEST_DIR/vault/records/example.txt.enc`.

### Utility & Production CLI Capabilities
- **Batch & Wildcard Operations:** Encrypt or decrypt multiple files simultaneously (`kvault encrypt --in *.pdf --vault myvault`) using a single passphrase prompt.
- **Directory Hierarchy Archiving:** Pack and encrypt recursive folder trees (`kvault encrypt --dir /path/to/folder --vault myvault`) preserving directory depth, subfolders, and relative paths.
- **Cryptographic Audit In-Place:** Perform HMAC integrity verification without writing plaintext to disk (`kvault verify --all --vault myvault`).
- **Tabular Record Inventory:** List stored vault records with plaintext sizes, stored sizes, POSIX permissions, modification timestamps, and advisory lock statuses (`kvault list --vault myvault`).
- **Safe Record Deletion:** Remove records safely under exclusive advisory mutex (`kvault rm --file example.txt --vault myvault`).
- **Multi-Pass Source Shredding:** Securely wipe plaintext source files (`--shred` / `--wipe`) with CSPRNG entropy (`getrandom`), zeroization, and `fsync()` before unlinking.

## Run the desktop GUI

On a Linux desktop or Ubuntu under WSLg, start the native interface with:

```bash
./build/kvault-gui
```

Choose a vault folder and initialize it. The modernized interface provides three functional tabs:
1. **Encrypt Files / Folders:** Multi-file selector, directory selector, source shred toggle, and passphrase entry.
2. **Decrypt Record:** Record dropdown, output destination chooser, and authenticated restoration.
3. **Vault Inventory & Audit:** Real-time table view of stored records (sizes, versions, permissions, timestamps, lock states), with interactive buttons to **Verify Integrity (HMAC)**, **Audit All Records**, and safely **Delete Record**.

> **Passphrase handling:** The CLI supports interactive masked input (with terminal echo disabled via POSIX `termios`), pipeline streaming (`--key-stdin`), the `KVAULT_KEY` environment variable, or explicit command-line flags (`--key`). When `--key` is passed via `argv`, process memory is immediately scrubbed in-place to prevent inspection via `ps aux` or `/proc/<pid>/cmdline`. The GUI masks typed passphrases and securely wipes memory upon completion.

The full build and operator workflow is in [`docs/RUNBOOK.md`](docs/RUNBOOK.md); architecture and record format are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); systems engineering rationale and real-world design decisions are in [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md); technical interview defense and architecture FAQ are in [`docs/INTERVIEW_CHEAT_SHEET.md`](docs/INTERVIEW_CHEAT_SHEET.md).

## Record format

Version 3 records contain a packed 96-byte header followed by AES-CBC ciphertext. Version 3 derives distinct keys for encryption ($K_{\text{enc}}$) and authentication ($K_{\text{mac}}$) via RFC 2898 multi-block PBKDF2 and serializes all integer fields in canonical Little-Endian wire format. The HMAC-SHA256 covers the header with its tag field set to zero, followed by the ciphertext. The reader retains backward compatibility with version 2 and version 1 records.

| Offset | Size | Field | Purpose |
| ---: | ---: | --- | --- |
| `0x00` | 4 bytes | Magic | Identifies a KernelVault record (`KVLT` = `0x4B564C54`). |
| `0x04` | 4 bytes | Version | Current writer version is `3` (Canonical LE + Dual Keys). |
| `0x08` | 16 bytes | Salt | Per-record PBKDF2 salt. |
| `0x18` | 16 bytes | IV | AES-CBC initialization vector. |
| `0x28` | 8 bytes | Original size | Plaintext length before padding (Little-Endian). |
| `0x30` | 8 bytes | Payload size | Ciphertext length in bytes (Little-Endian). |
| `0x38` | 32 bytes | HMAC | Record authentication tag ($K_{\text{mac}}$). |
| `0x58` | 4 bytes | POSIX Mode | POSIX permission bits (`st_mode & 07777`, Little-Endian). |
| `0x5C` | 4 bytes | Modified Epoch | Modification timestamp (seconds since Unix epoch, Little-Endian). |
| `0x60` | Variable | Ciphertext | AES-256-CBC encrypted payload ($K_{\text{enc}}$). |

All multi-byte header integers are encoded in Little-Endian wire format for deterministic cross-architecture compatibility.

## Driver workflow

Build and load the module on a Linux test machine or VM with matching headers:

```bash
make -C driver
sudo insmod driver/kvault.ko
ls -l /dev/kvault
sudo dmesg | tail -n 20
```

Then run the CLI as a user permitted to open `/dev/kvault`. Device-node permissions are controlled by the host's device-management policy. Do not make the node world-writable. Unload the module after testing:

```bash
sudo rmmod kvault
```

Kernel modules run with kernel privileges. Use a disposable Linux VM for driver testing and review the source before loading it.

## Tests and CI

Build and run the C++ test suite:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The current GoogleTest suite covers file-descriptor ownership, POSIX locking, atomic file writes, and vault-level encryption/decryption and integrity behavior. It does **not** automate loading or exercising the kernel module; driver validation requires a Linux environment with suitable headers and privileges. See [`docs/TESTING.md`](docs/TESTING.md) for the validation scope.

GitHub Actions builds and tests the user-space project with GCC and Clang and compiles the driver against installed Linux headers.

## Repository layout

```text
.
├── .github/workflows/       GitHub Actions build and test workflow
├── driver/                  C Linux character-device driver and Kbuild files
├── include/                 C++ interfaces and shared driver IOCTL definitions
├── src/                     C++20 CLI, optional Qt GUI, vault engine, and POSIX components
├── tests/                   GoogleTest C++ test suite
├── docs/                    Architecture, runbook, and design decisions
├── CMakeLists.txt           Linux-only CMake build
├── LICENSE                  MIT OR GPL-2.0 dual license
└── README.md                Project overview and documentation
```

## License

KernelVault is dual-licensed under the MIT License or GNU General Public License version 2. See [`LICENSE`](LICENSE).
