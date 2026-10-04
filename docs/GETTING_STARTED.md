# Getting Started with KernelVault: Complete Beginner's Guide & Tutorial

Welcome to **KernelVault**! Whether you are a Linux enthusiast, a student, a security researcher, or a systems software engineer, this tutorial will guide you step-by-step from zero knowledge to mastering secure encrypted file storage on Linux.

---

## Table of Contents
1. [Core Concepts in Plain English](#1-core-concepts-in-plain-english)
2. [Prerequisites & 1-Minute Setup](#2-prerequisites--1-minute-setup)
3. [Tutorial 1: Creating Your First Secure Vault](#3-tutorial-1-creating-your-first-secure-vault)
4. [Tutorial 2: Storing, Listing & Restoring Files](#4-tutorial-2-storing-listing--restoring-files)
5. [Tutorial 3: Safeguarding Entire Folders & Directory Trees](#5-tutorial-3-safeguarding-entire-folders--directory-trees)
6. [Tutorial 4: Cryptographic Audits & Anti-Forensic Shredding](#6-tutorial-4-cryptographic-audits--anti-forensic-shredding)
7. [Tutorial 5: Using the Native Desktop GUI](#7-tutorial-5-using-the-native-desktop-gui)
8. [Tutorial 6: Enabling the Linux Kernel Driver (Optional)](#8-tutorial-6-enabling-the-linux-kernel-driver-optional)
9. [Common Beginner Gotchas & Solutions](#9-common-beginner-gotchas--solutions)

---

## 1. Core Concepts in Plain English

Before typing commands, let's understand how KernelVault works under the hood:

```text
 ┌────────────────┐         ┌───────────────────────────────┐         ┌────────────────────────┐
 │ Plaintext File │  ────>  │    KernelVault Engine (CLI)   │  ────>  │ Encrypted Vault Record │
 │  "secret.txt"  │         │   (AES-256-CBC + HMAC-SHA256) │         │  "records/secret.enc"  │
 └────────────────┘         └───────────────────────────────┘         └────────────────────────┘
                                           ▲
                                           │
                              Passphrase: "MyPassword#1"
```

* **The Vault Folder:** A dedicated directory on your disk (e.g. `~/my_vault`) locked down to permissions `0700` (meaning *only your user account* can enter or read it).
* **Records:** Inside the vault, files are stored with strong **AES-256-CBC encryption**. Each file has a packed **96-byte header** preserving your original file permissions and timestamps.
* **Integrity Tag (HMAC-SHA256):** A cryptographic digital seal over every record. If an attacker modifies even a single byte of your file on disk, KernelVault detects the tampering and refuses to decrypt it.
* **Advisory Lockfile:** KernelVault creates lightweight locks (`.lock`) to ensure that two processes never write to the same file simultaneously.
* **Hardware Accelerator Driver (`/dev/kvault`):** An optional Linux kernel module that offloads the heavy math directly to your CPU's hardware cryptographic instructions (AES-NI). If the driver is not loaded, KernelVault automatically uses its built-in software engine—you never have to worry about missing features.

---

## 2. Prerequisites & 1-Minute Setup

### Supported Systems
* **OS:** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12, Arch Linux, Fedora, or WSL2 (Windows Subsystem for Linux with Ubuntu).
* **Architecture:** x86_64 or ARM64.

### Step 1: Install Dependencies
Open your Linux terminal and run:

```bash
# On Ubuntu / Debian:
sudo apt update
sudo apt install -y build-essential cmake libgtest-dev qt6-base-dev
```

### Step 2: Clone the Repository
Clone the KernelVault codebase into your Linux user home directory:

```bash
git clone https://github.com/sky-ruler/KernelVault.git
cd KernelVault
```

### Step 3: Build KernelVault
From the repository root directory:

```bash
# 1. Configure the build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_GUI=ON

# 2. Compile all tools in parallel
cmake --build build --parallel

# 3. Verify that all 34 automated tests pass on your machine
ctest --test-dir build --output-on-failure
```

You now have two executables ready:
- `build/kvault`: High-speed command-line interface.
- `build/kvault-gui`: Modern desktop graphical window.

---

## 3. Tutorial 1: Creating Your First Secure Vault

Let's initialize a new vault folder named `secure_vault`:

```bash
./build/kvault init --vault ~/secure_vault
```

**What happened behind the scenes?**
1. Created `~/secure_vault` with strict `0700` POSIX directory permissions (`rwx------`).
2. Created subdirectories: `~/secure_vault/records/` and `~/secure_vault/locks/`.
3. Generated a cryptographically random master salt and created `vault.meta`.

---

## 4. Tutorial 2: Storing, Listing & Restoring Files

### Step 1: Create a test document
```bash
echo "Financial accounts and private cryptographic keys." > private_note.txt
```

### Step 2: Encrypt and store the document in your vault
```bash
./build/kvault encrypt --vault ~/secure_vault --in private_note.txt
```
*(You will be prompted to enter and confirm a secure passphrase. Terminal echo is masked for security).*

### Step 3: View your vault inventory (`kvault list`)
You can view all records stored inside your vault with human-readable sizes, permissions, and timestamps:

```bash
./build/kvault list --vault ~/secure_vault
```
*Output:*
```text
========================================================================================================
Record Name          Version    Plaintext Size   Stored Size   POSIX Mode  Last Modified        Lock Status
========================================================================================================
private_note.txt     V3         50 B             64 B          -rw-rw-r--  2026-10-04 04:15:00  UNLOCKED   
========================================================================================================
Total Stored Records: 1 (64 B encrypted storage consumed)
```

### Step 4: Delete the original plaintext file
Now you can safely delete your original file:
```bash
rm private_note.txt
```

### Step 5: Decrypt and restore the document
When you need your file back:
```bash
./build/kvault decrypt --vault ~/secure_vault --file private_note.txt --out recovered_note.txt
```
*(Enter your passphrase. KernelVault authenticates the HMAC tag and restores the exact original file).*

Verify the restored content:
```bash
cat recovered_note.txt
```

---

## 5. Tutorial 3: Safeguarding Entire Folders & Directory Trees

Most encryption tools only handle single files, requiring you to manually run `tar` first. KernelVault has built-in recursive folder packaging:

### Step 1: Create a sample project folder
```bash
mkdir -p my_project/code
echo "int main() { return 0; }" > my_project/code/main.c
echo "# Project documentation" > my_project/README.md
chmod 755 my_project/code/main.c
```

### Step 2: Encrypt the entire folder in one command
```bash
./build/kvault encrypt --vault ~/secure_vault --dir my_project
```

### Step 3: Restore the entire directory tree
To unpack and restore the folder structure anywhere on your system:
```bash
./build/kvault decrypt --vault ~/secure_vault --file my_project.kvdir --out-dir ~/restored_workspace
```

Inspect the restored tree:
```bash
ls -la ~/restored_workspace/my_project/code/main.c
```
Notice that:
* The subfolder `code/` was automatically recreated.
* The original executable permissions (`0755`) and modification timestamps were preserved down to the second.
* Protection is built-in: KernelVault scans every file in the archive to block **Zip-Slip** attacks.

---

## 6. Tutorial 4: Cryptographic Audits & Anti-Forensic Shredding

### In-Place Integrity Auditing (`kvault verify`)
How do you know if an encrypted file has been tampered with or corrupted without extracting it to disk?
Use `verify`:

```bash
./build/kvault verify --vault ~/secure_vault --all
```
KernelVault reads the ciphertext in streaming chunks, recomputes the HMAC-SHA256 signature, and confirms integrity:
```text
[*] Auditing cryptographic HMAC for record: private_note.txt.vault ... [VERIFIED OK]
[*] Auditing cryptographic HMAC for record: my_project.kvdir.vault ... [VERIFIED OK]

Verification Audit Complete: 2 passed, 0 failed.
```

### Anti-Forensic File Shredding (`--shred`)
Standard `rm` only removes the file index entry; the unencrypted data remains on your physical disk sectors and can be recovered using forensics tools.

When encrypting sensitive files, pass `--shred` (or `--wipe`):
```bash
./build/kvault encrypt --vault ~/secure_vault --in sensitive_passwords.txt --shred
```
KernelVault will:
1. Encrypt the file into the vault.
2. Overwrite the original source file sectors with random entropy from the Linux kernel CSPRNG (`getrandom`).
3. Overwrite the sectors with zeroes.
4. Issue an `fsync()` system call forcing the storage controller to commit the wipe to physical media.
5. Safely unlink the file.

---

## 7. Tutorial 5: Using the Native Desktop GUI

If you prefer a graphical interface, launch:

```bash
./build/kvault-gui
```
*(Or launch **KernelVault** from your Ubuntu / Debian Application Drawer if installed via `.deb` package).*

The desktop interface opens with 3 intuitive tabs and persistent directory memory:

### 1. Setting Your Vault
Enter or browse to your vault directory (e.g. `~/my_vault`) and click **"Initialize / Open Vault"**. KernelVault automatically remembers your chosen vault path and restore destinations across restarts using persistent settings.

### 2. Encrypting Files & Folders
- **Drag-and-Drop Ingestion:** Simply drag files or folders from Nautilus, Dolphin, or your desktop directly into the KernelVault window. The app automatically stages the path and selects the Encrypt tab.
- **Passphrase Usability & Match Verification:** Enter your passphrase, click the `👁 Show` eye toggle to confirm spelling, and type it into the confirmation field. A real-time badge updates (`✓ Passphrases match` or `✗ Passphrases do not match`), locking the Encrypt button until they align to prevent accidental lockouts.
- **Anti-Forensic Shredding:** Check *"Securely shred source files after encryption"* to perform multi-pass CSPRNG overwriting and `fsync()` before deleting the plaintext source.
- **Vault Collision Guard:** If a file with the same name already exists inside the vault, KernelVault presents a warning prompt so you never clobber existing records by mistake.

### 3. Decrypting Records & Collision Prevention
- **Smart Auto-Updating Destination Path:** When you select an encrypted record from the dropdown, the **Destination File/Directory** field automatically updates with the original filename or unpacked folder name (stripping `.kvdir` for folder archives).
- **Disk Collision Detection:** If a file or folder with that name already exists in the destination folder, KernelVault immediately displays a yellow warning: `⚠️ Target already exists on disk. Collision detected.`
- **Instant Auto-Rename:** An inline **"Auto-Rename (1)"** button appears next to the path. Clicking it safely appends a non-colliding numeric suffix (e.g., `report (1).pdf`).
- **Interactive 3-Way Safety Dialog:** If you click **"Decrypt Record"** while a collision exists and *"Allow overwrite"* is unchecked, KernelVault presents a 3-way dialog:
  - **Auto-Rename:** Restores to a safe, non-colliding filename.
  - **Overwrite:** Atomically replaces the existing file on disk.
  - **Cancel:** Aborts the operation without touching your disk.

### 4. Vault Inventory, Search & Context Menus
- **Live Search & Filter:** Use the instant search bar above the record table to filter records in real-time across filenames, dates, POSIX permission bits, and status.
- **Right-Click Context Menu:** Right-click any record row for direct actions:
  - **Restore / Decrypt Record:** Immediately stages the record for decryption.
  - **Verify Integrity (HMAC):** Cryptographically verifies the authentication tag without decrypting.
  - **Copy Record Name:** Copies the record filename to the clipboard.
  - **Delete Record:** Safely deletes the record and its advisory lockfile.
- **Visual Progress:** An animated progress bar provides visual feedback during key derivation and large-payload streaming.

---

## 8. Tutorial 6: Enabling the Linux Kernel Driver (Optional)

KernelVault includes an optional Linux character driver (`/dev/kvault`) that offloads cryptographic transformations to the **Linux Kernel Crypto API**.

### Automated Verification Script
To compile, insert, test, and cleanly unload the driver automatically:
```bash
sudo ./scripts/test_driver.sh
```

### Permanent Non-Root Access via Udev Rule
If you want standard non-root desktop users to access `/dev/kvault` without `sudo`:
```bash
sudo cp packaging/udev/99-kvault.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## 9. Common Beginner Gotchas & Solutions

| Issue / Error | Cause | Instant Solution |
| :--- | :--- | :--- |
| `Missing required parameter: --vault <path>` | Every command requires specifying which vault folder to operate on. | Add `--vault ~/my_vault` to your command. |
| `Passphrase verification failed / HMAC mismatch` | The password typed does not match the password used during encryption. | Retype the correct passphrase. KernelVault aborts before any plaintext is touched. |
| `Permission denied while opening /dev/kvault` | The kernel driver node defaults to root-only if udev rules are not active. | Run `sudo chmod 666 /dev/kvault` or install `packaging/udev/99-kvault.rules`. *(KernelVault automatically falls back to software if access is denied).* |
| `Destination file already exists` | Attempting to decrypt over an existing file. | In the CLI, specify a different output filename with `--out <new_name>`. In the GUI, click the **"Auto-Rename (1)"** button or check *"Allow overwrite"*. |
| `kvault-gui does not launch after installing .deb` | Missing Qt6 runtime shared libraries (`libQt6Widgets.so.6`). | Run `sudo apt update && sudo apt install -y libqt6widgets6` (or install packages using `sudo apt install ./kvault-*.deb` instead of bare `dpkg -i`). |
| `Collision detected: yellow warning banner in GUI` | The restored file or directory name already exists in the target destination folder. | Click **"Auto-Rename (1)"** to append a safe numeric suffix, or check *"Allow overwrite"* if you intend to replace the file. |
