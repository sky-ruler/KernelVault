# Linux Runbook

This guide builds and exercises the KernelVault C++ CLI, optional native Qt desktop interface, and Linux character driver on a Linux machine or virtual machine. The CLI and GUI run on Ubuntu under WSL2 with WSLg; driver loading and testing should use a suitable Linux VM or machine.

## 1. Install build dependencies

On Debian or Ubuntu, install the CLI, test, and GUI dependencies:

```bash
sudo apt update
sudo apt install -y git build-essential cmake libgtest-dev qt6-base-dev
```

If starting from a fresh clone, clone it into a Linux filesystem directory. In WSL, use `$HOME` (for example, `~/KernelVault`) rather than `/mnt/c`; Windows-mounted paths may prevent CMake from creating generated files. CMake can fetch GoogleTest if the system package cannot be found, which requires network access.

```bash
git clone <repo-url> "$HOME/KernelVault"
cd "$HOME/KernelVault"
```

## 2. Build the CLI and tests

Run commands from the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_GUI=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The CLI is `build/kvault`; the GUI is `build/kvault-gui`. To build only the CLI, pass `-DBUILD_GUI=OFF` and omit the Qt development package.

## Optional: launch the desktop GUI

On a Linux desktop or Ubuntu under WSLg:

```bash
./build/kvault-gui
```
*(Or launch **KernelVault** from your desktop Application Drawer).*

The modernized interface provides persistent directory memory and three functional tabs:
1. **Encrypt Files / Folders:** Multi-file and directory selection, drag-and-drop ingestion, source shredding toggle, duplicate record warning guards, and passphrase entry with eye show/hide toggle and real-time confirmation match badge.
2. **Decrypt Record:** Record dropdown, smart auto-updating target paths, disk collision detection with yellow warning banners, inline **"Auto-Rename (1)"** button, overwrite toggles, and safe 3-way conflict dialogs.
3. **Vault Inventory & Audit:** Real-time table view of stored records with an instant live search filter, right-click context menus (**Restore / Decrypt**, **Verify Integrity (HMAC)**, **Copy Record Name**, **Delete Record**), and visual progress marquee.

## 3. Create test input and vault

```bash
set -eu
TEST_DIR="$(mktemp -d /tmp/kvault-test.XXXXXX)"
printf 'KernelVault sample data 1\n' > "$TEST_DIR/sample1.txt"
printf 'KernelVault sample data 2\n' > "$TEST_DIR/sample2.txt"
mkdir -p "$TEST_DIR/my_folder"
printf '#!/bin/sh\necho "Hello from inside vault"\n' > "$TEST_DIR/my_folder/app.sh"
chmod 0755 "$TEST_DIR/my_folder/app.sh"

./build/kvault init --vault "$TEST_DIR/vault"
```

## 4. Encrypt, list, audit, and decrypt

### Passphrase Handling
The CLI supports multiple secure passphrase input methods:
- **Interactive Masked Prompt (Default):** Prompts with terminal echo disabled via POSIX `termios`.
- **Standard Input Pipeline:** Pipe passphrases securely via `--key-stdin` (e.g. `echo -n 'secret' | ./build/kvault ... --key-stdin`).
- **Environment Variable:** Set `export KVAULT_KEY='secret'`.
- **Command-Line Flag (`--key`):** Memory containing the raw argument in `argv` is scrubbed in-place immediately upon ingestion to prevent inspection via `ps aux` or `/proc/<pid>/cmdline`.

### Batch & Wildcard Encryption with Shredding
Encrypt multiple files in a single pass with one passphrase prompt:
```bash
./build/kvault encrypt --vault "$TEST_DIR/vault" --in "$TEST_DIR"/sample*.txt --key 'sample-passphrase'
```

Encrypt an entire directory tree recursively, preserving subfolders, permissions, and timestamps:
```bash
./build/kvault encrypt --vault "$TEST_DIR/vault" --dir "$TEST_DIR/my_folder" --key 'sample-passphrase'
```

### Tabular Vault Inventory (`kvault list`)
Inspect all vault records with human-readable sizes, POSIX modes, timestamps, and lock status:
```bash
./build/kvault list --vault "$TEST_DIR/vault"
```

### In-Place Cryptographic Audit (`kvault verify`)
Verify cryptographic HMAC-SHA256 integrity without writing plaintext to disk:
```bash
./build/kvault verify --vault "$TEST_DIR/vault" --all --key 'sample-passphrase'
```

### Batch Decryption & Restoration
Restore all records into a target destination directory:
```bash
./build/kvault decrypt --vault "$TEST_DIR/vault" --all --out-dir "$TEST_DIR/restored" --key 'sample-passphrase'

cmp "$TEST_DIR/sample1.txt" "$TEST_DIR/restored/sample1.txt"
ls -la "$TEST_DIR/restored/my_folder/app.sh"
echo 'Round trip verified: all restored files and directories match.'
```

### Safe Record Deletion (`kvault rm`)
Safely remove records and associated locks under exclusive POSIX advisory mutex:
```bash
./build/kvault rm --vault "$TEST_DIR/vault" --file sample1.txt --force
```

### Empirical Micro-Benchmarking (`kvault bench`)
Measure latency and streaming throughput across key derivation, cipher transformations, and HMAC-SHA256:
```bash
./build/kvault bench --size-mb 16
```

## 5. Build and load the Linux driver (optional)

KernelVault includes an automated driver test harness that builds, loads, runs an end-to-end cryptographic test round-trip through `/dev/kvault`, and cleanly unloads:
```bash
sudo ./scripts/test_driver.sh
```

Or perform manual lifecycle operations:
```bash
sudo apt install -y kmod linux-headers-$(uname -r)
make -C driver
sudo insmod driver/kvault.ko
ls -l /dev/kvault
sudo dmesg | tail -n 20
```

To grant non-root desktop access to `/dev/kvault`, install the udev rule:
```bash
sudo cp packaging/udev/99-kvault.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

When the device cannot be opened, the CLI seamlessly uses its built-in software cipher fallback.

Unload the module after testing:

```bash
sudo rmmod kvault
```

## 6. Inspect vault status

```bash
./build/kvault status --vault "$TEST_DIR/vault"
```

## 7. Clean up

```bash
rm -rf -- "$TEST_DIR"
```

This removes only the temporary test directory created by `mktemp`. Leave the build directory intact if you want to continue using the executable.

## Troubleshooting

- **`cmake` is not recognized in PowerShell:** open the Ubuntu/WSL terminal and run the Linux build commands there.
- **CMake reports `Operation not permitted` under WSL:** clone the repository under `$HOME` and build there. If keeping the checkout under `/mnt/c`, set the build directory to a Linux path such as `$HOME/kvault-build`.
- **GUI does not open in WSL:** confirm WSLg is available; otherwise use a Linux desktop or VM. The CLI continues to work without a graphical display.
- **Driver build or module loading fails in WSL:** use a Linux VM or machine with matching kernel headers and permission to load modules. The CLI and GUI can still run in their user-space fallback mode.
- **`cmp` reports a difference:** confirm decryption used the same passphrase and inspect the command's exit status; `cmp` prints nothing when files match. Check that the reported recovered byte count matches the source file size.
- **Kernel headers are missing:** install headers matching the target kernel or provide the desired Kbuild directory with `make -C driver KDIR=/path/to/kernel/build`.
- **`insmod` fails:** inspect `sudo dmesg`; check that the module was built against the target kernel and that kernel module loading is permitted.
- **The driver is unavailable to the CLI:** inspect `ls -l /dev/kvault` and use the host's normal group/udev policy to grant access. CLI fallback remains available.
- **Authentication fails:** use the exact passphrase used during encryption and ensure the encrypted record was not modified.
- **`kvault-gui` fails to launch after installing `.deb` package:** If installed using bare `dpkg -i`, run `sudo apt install -f` or `sudo apt install -y libqt6widgets6` to install the required Qt6 shared library dependencies.
- **Collision detected warning in GUI:** KernelVault prevents accidental overwrites when a restored file or directory already exists on disk. Click "Auto-Rename (1)" to safely append a numeric suffix or check "Allow overwrite".
