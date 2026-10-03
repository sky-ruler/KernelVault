# Engineering Rationale & Design Decisions

This document details the architectural choices, systems engineering primitives, and real-world industrial precedents behind **KernelVault**. It explains not only *how* the system works, but *why* each component was engineered the way it was.

---

## 1. Executive Summary & Philosophy

At first glance, a file encryption utility can seem trivial—a basic script in Python or Go can encrypt data using OpenSSL in fewer than ten lines of code.

**KernelVault was not built to be a simple encryption script.** It is a systems-programming architecture project designed to explore the boundary between **Linux User Space and Kernel Space (Ring 0)**. 

The encryption workload acts as a practical vehicle to demonstrate:
1. **Hardware & Accelerator Simulation:** Interfacing with kernel drivers via IOCTL rather than relying entirely on userland libraries.
2. **Crash-Resilient Storage:** Preventing data corruption during sudden power loss or kernel panics via atomic file replacement (`fsync` + `renameat2` + directory synchronization).
3. **Multi-Process Concurrency:** Protecting shared resources with POSIX advisory locks and isolated per-session kernel states (`struct kvault_session`).
4. **Anti-Forensic Memory Hygiene & Pinning:** Preventing compiler dead-store elimination (`secureZero` + `memzero_explicit`) and pinning master keys to physical RAM (`mlock`) to prevent swap paging.
5. **Cryptographic Protocol Discipline:** Enforcing distinct derived keys for cipher and MAC (RFC 2898 multi-block PBKDF2: $K_{\text{enc}} \neq K_{\text{mac}}$) and verified Encrypt-then-MAC with canonical wire formatting.
6. **Constant-Memory Streaming ($O(1)$ RAM):** Processing arbitrary-sized files (from 1 KB to 1 TB) in bounded 64 KiB chunks with a stateful streaming HMAC context.

---

## 2. Component Deep Dive: Why It Exists & Industry Precedents

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   KernelVault System                                   │
├──────────────────────────┬─────────────────────────────┬───────────────────────────────┤
│ Component                │ Engineering Reason          │ Real-World Industrial Analogy │
├──────────────────────────┼─────────────────────────────┼───────────────────────────────┤
│ Linux Character Driver   │ Direct Ring 0 IOCTL boundary│ Hardware Security Modules, TPM│
│ Per-Session Concurrency  │ Zero-contention multi-stream│ Linux DRM / GPU render nodes  │
│ Atomic File Writer       │ Zero-corruption persistence │ SQLite WAL, Git Object Store  │
│ POSIX fcntl Locking      │ Multi-process mutual exclude│ dpkg, package managers, DBMS  │
│ Memory Pinning (mlock)   │ Prevent swap-file key leaks │ OpenSSH, GnuPG, Linux Keyring │
│ memzero_explicit()       │ Stop dead-store elimination │ OpenSSL, Linux Kernel Core    │
│ Dual Derived Keys        │ NIST SP 800-108 key hygiene │ TLS 1.3, Signal Protocol      │
│ Constant-Memory Stream   │ O(1) RAM bounded processing │ Linux VFS, Streaming pipelines│
└──────────────────────────┴─────────────────────────────┴───────────────────────────────┘
```

---

### A. The Custom Linux Character Driver (`/dev/kvault`) & Per-Session Architecture

#### The Decision
Rather than executing AES-256 transformations purely in user space, KernelVault implements an out-of-tree Linux character-device driver ([`driver/kvault_module.c`](../driver/kvault_module.c)) that binds to the in-kernel **Linux Crypto API** (`crypto_alloc_skcipher`). Communication flows across a typed IOCTL boundary defined in [`include/kvault_ioctl.h`](../include/kvault_ioctl.h).

Each open file descriptor allocates an isolated `struct kvault_session` in `kvault_open()`, equipped with its own transform handle, session keys, and pre-allocated IO bounce buffers.

#### The Reality Check
For pure software AES on a CPU, running inside the kernel introduces context-switching overhead (`copy_from_user` / `copy_to_user`). It does not accelerate execution compared to user-space hardware AES-NI instructions.

#### The Real-World Precedent
This architecture mirrors how **dedicated cryptographic hardware** interfaces with the operating system:
* **Hardware Security Modules (HSMs) & TPMs:** Security chips like `/dev/tpm0` do not expose user-space functions; they communicate across character drivers and serialized command buffers.
* **PCIe Crypto Accelerators:** High-throughput enterprise accelerators (e.g., **Intel QAT** - QuickAssist Technology) offload cryptographic workloads from server CPUs via kernel drivers and IOCTL control queues.
* **Multi-Session Isolation:** Just as modern Linux GPU drivers (`/dev/dri/renderD*`) allocate private context buffers per process, KernelVault isolates sessions per file descriptor, allowing completely concurrent multi-process access without global locks.

---

### B. Atomic File Durability (`fsync` + Atomic `rename` + Directory Sync)

#### The Decision
[`src/AtomicFileWriter.cpp`](../src/AtomicFileWriter.cpp) writes all output to a private, hidden temporary file with `O_NOFOLLOW | O_EXCL` flags, synchronizes file data with `fsync()`, commits the file using `renameat2()` (with `RENAME_NOREPLACE`), and flushes the parent directory (`syncParentDirectory()`).

```text
Write to .file.tmp.PID.Rand ──► fsync() [Force Cache Flush] ──► renameat2() ──► fsync(parent_dir)
```

#### The Reality Check
Naively calling `fopen("vault.enc", "w")` and `fwrite()` writes directly into the Linux page cache in RAM. If the system loses power or crashes mid-write:
* The original file is already truncated and lost.
* The target file contains half-written data or null bytes.
* The vault record is permanently corrupted.

#### The Real-World Precedent
* **Git:** When creating objects or updating references (`.git/objects/`, `.git/refs/`), Git never writes in-place. It writes to a temporary file and issues an atomic `rename()` to ensure repository integrity cannot be corrupted mid-commit.
* **Databases (SQLite & PostgreSQL):** All modern databases use Write-Ahead Logs (WAL) and atomic rename operations with directory synchronization to guarantee ACID durability across unexpected reboots.

---

### C. POSIX Advisory File Locking (`fcntl`)

#### The Decision
[`src/FileLock.cpp`](../src/FileLock.cpp) implements POSIX advisory locking via `fcntl(fd, F_SETLK, &fl)` before reading or writing any record.

#### The Reality Check
In multi-user or automated Linux environments (e.g., CLI tools invoked by background cron jobs or simultaneous terminal windows), race conditions occur when two processes access the same record concurrently. Without locking, interleaved writes corrupt the file.

#### The Real-World Precedent
* **System Daemons & Package Managers:** `dpkg` and `apt` employ file locks (`/var/lib/dpkg/lock`) to prevent concurrent package management operations from breaking system state.
* **SQLite:** Employs POSIX `fcntl` byte-range locks to allow multiple simultaneous readers while restricting writers to strict mutual exclusion.

---

### D. Anti-Forensic Memory Hygiene & Swapping Defense (`mlock` + `secureZero`)

#### The Decision
1. **Memory Pinning:** Master keys are held exclusively inside `PinnedMemory<N>` ([`include/PinnedMemory.hpp`](../include/PinnedMemory.hpp)), which invokes `::mlock()` on allocation to guarantee sensitive key material is never written to unencrypted swap space or hibernation disk images.
2. **Compiler Barrier Scrubbing:** Buffers are sanitized using:
   * In the kernel: `memzero_explicit()` in [`driver/kvault_module.c`](../driver/kvault_module.c).
   * In user space: `KeyDerivation::secureZero()` in [`src/KeyDerivation.cpp`](../src/KeyDerivation.cpp), utilizing `volatile unsigned char*` pointers followed by `std::atomic_thread_fence(std::memory_order_seq_cst)`.

#### The Reality Check
A standard `memset(key, 0, sizeof(key))` placed at the end of a function is often **silently removed by the compiler** under optimization levels `-O2` or `-O3` because the write is treated as a "dead store". Furthermore, unpinned memory in virtual memory systems can be swapped out to `/dev/sda` swap partitions where keys persist on cold disk media indefinitely.

#### The Real-World Precedent
* **OpenSSH & GnuPG:** Pin memory holding private RSA/Ed25519 keys via `mlock()` and use memory-fence scrubbing routines (`explicit_bzero`) to defend against cold-boot and swap forensic recovery.

---

### E. Authenticated Encryption & Key Hygiene (RFC 2898 Multi-Block PBKDF2)

#### The Decision
KernelVault implements **Version 3** authenticated records:
1. **Dual Derived Keys:** Uses RFC 2898 multi-block PBKDF2 to derive distinct 256-bit keys:
   $$K_{\text{enc}} = \text{PBKDF2}(P, S, 100000, \text{Block } 1)$$
   $$K_{\text{mac}} = \text{PBKDF2}(P, S, 100000, \text{Block } 2)$$
   $K_{\text{enc}} \neq K_{\text{mac}}$ strictly prevents key-reuse vulnerabilities (NIST SP 800-108).
2. **Canonical Wire Format:** All 96-byte header fields (`magic`, `version`, `original_size`, `payload_size`) are encoded in Little-Endian format (`htole32`/`htole64`), ensuring identical binary representations across architectures.
3. **Encrypt-then-MAC:** The 96-byte header (with empty HMAC field) and entire ciphertext stream are authenticated with HMAC-SHA256. During decryption, authentication is verified **before** any plaintext is written or decryption executed.

```text
Record Header (96 Bytes) + AES-CBC Ciphertext
              │
              ▼
   [ Verify HMAC-SHA256 ] ────► Fail? ──► ABORT (No disk writes, transform never invoked)
              │
              ▼ (Success)
   [ Decrypt AES Payload in 64 KiB chunks ]
              │
              ▼
   [ Atomic Output Write ]
```

#### The Reality Check
Unauthenticated CBC mode is vulnerable to **Padding Oracle Attacks** (e.g., POODLE) and bit-flipping attacks. Reusing the same master key for both AES encryption and HMAC authentication compromises cryptographic security proofs.

#### The Real-World Precedent
* **TLS 1.3 & Signal Protocol:** Demand strict key separation between cipher and authentication keys derived from a single secret via HKDF or multi-block KDF.

---

### F. Constant-Memory Streaming ($O(1)$ RAM)

#### The Decision
Both `encryptFile` and `decryptFile` stream data in bounded 64 KiB chunks. 
* In `KeyDerivation`, a stateful streaming `HmacContext` computes and verifies HMAC-SHA256 incrementally across chunks.
* `decryptFile` uses a 2-pass streaming verification pipeline: Pass 1 authenticates the record chunk-by-chunk without storing the payload in memory; Pass 2 streams plaintext decryption directly into the atomic file writer.

#### The Reality Check
Loading entire files into `std::vector<uint8_t>` exhausts process RAM and triggers out-of-memory kernel OOM-killer crashes on files larger than available RAM.

---

### G. POSIX Metadata Preservation (`posix_mode` & `mtime_epoch`)

#### The Decision
KernelVault captures `st.st_mode & 07777` (permission bits, setuid/setgid, and executable `+x` flags) and `st.st_mtime` (seconds since Unix epoch) via `::stat()`. These are serialized directly into bytes `0x58` and `0x5C` of the 96-byte `VaultHeader` in Little-Endian format. Upon atomic decryption commit, permissions are restored via `::chmod()` and timestamps are restored via `::utimensat()`.

#### The Reality Check
Naive encryption utilities discard filesystem metadata, treating all files as generic byte streams. When restored, executable scripts lose their `+x` flags and cannot be run, sensitive files default to world-readable umask settings, and modification timestamps are set to the current instant—breaking incremental backup tools (`rsync`), build systems (`make`), and audit logs.

#### The Real-World Precedent
* **POSIX Archivers (`tar`, `cpio`):** Preserve mode bits and timestamps to guarantee that restored file trees behave identically to the originals.
* **Database & File System Restores (`zfs send/recv`):** Preserves immutable file birth and modification timestamps across transport streams.

---

### H. Anti-Forensic Secure File Shredding (`--shred` / `--wipe`)

#### The Decision
[`VaultManager::shredFile`](../src/VaultManager.cpp) provides an anti-forensic deletion engine:
1. Opens the target file with `O_WRONLY | O_NOFOLLOW` (preventing symlink diversion attacks).
2. **Pass 1 (Entropy Overwrite):** Fills all blocks with cryptographically secure random bytes from the Linux kernel CSPRNG (`getrandom`).
3. Calls `::fsync()` to force dirty page cache lines onto physical drive platters/NAND flash.
4. **Pass 2 (Zeroization):** Overwrites all blocks with `0x00`.
5. Calls `::fsync()` again to ensure physical overwrite completion.
6. Unlinks the file via `std::filesystem::remove()` and zeroes the buffer in RAM.

#### The Reality Check
Calling POSIX `unlink()` or the shell command `rm` does **not** erase file content; it only decrements the inode reference count and frees disk blocks in the allocation bitmap. The unencrypted plaintext remains in physical storage sectors indefinitely, trivially recoverable with tools like `photorec` or `debugfs`.

#### The Real-World Precedent
* **GNU Coreutils `shred`:** Overwrites physical storage sectors with random patterns and zeroes before unlinking to defeat magnetic/solid-state forensic data carving.
* **DoD 5220.22-M & NIST SP 800-88:** Media sanitization standards demanding multi-pass random entropy overwrite and verification.

---

### I. Recursive Directory Vaulting & Path Traversal Defense

#### The Decision
KernelVault provides built-in directory archiving (`encryptDirectory` and `decryptDirectory`):
1. **Self-Contained Binary Format (`KVDIR1`):** Walks directory trees recursively via `std::filesystem::recursive_directory_iterator`, bundling entry types, permissions, timestamps, relative paths, and file payloads without spawning external child processes.
2. **Path Traversal Defense:** During unpacking, all paths are strictly sanitized: any entry containing `..` or leading `/` is immediately rejected.
3. **Atomic Decryption Gate:** Decrypts to a private temporary pack first; if the cryptographic HMAC check fails, extraction never begins.

#### The Reality Check
Invoking external `tar` or `zip` processes introduces `fork`/`exec` overhead and exposes the system to command injection. Furthermore, naive archive extractors are famously vulnerable to the **Zip Slip / Tar Slip** vulnerability, where malicious path strings like `../../../../etc/shadow` escape the destination directory and overwrite critical system configuration files.

---

### J. Empirical Micro-Benchmarking Engine (`kvault bench`)

#### The Decision
KernelVault embeds an automated cryptographic micro-benchmarking engine directly into the core binary (`kvault bench [--size-mb <N>]`), measuring:
1. PBKDF2 iteration speed (iterations per second) across 100,000 rounds.
2. AES-256-CBC streaming throughput across 64 KiB chunks.
3. HMAC-SHA256 streaming digest throughput in continuous $O(1)$ memory.
4. Integrated Encrypt-then-MAC streaming pipeline throughput.

#### The Reality Check
Systems engineering claims without empirical throughput figures are regarded as unverified theory in technical code reviews. Integrating the benchmark directly into the binary allows continuous performance regression tracking in CI/CD without requiring external profilers (`perf`, `valgrind`, `gprof`).

#### The Real-World Precedent
* **OpenSSL `openssl speed`:** The industry-standard benchmarking tool for comparing cipher algorithms across CPU architectures.
* **Go Standard Library `testing.B`:** Built-in programmatic benchmark runner ensuring that memory allocations and algorithm iterations are audited continuously.

---

### K. Native Debian Packaging & Udev Security Policy

#### The Decision
Rather than relying on generic distribution scripts or isolated containers (Flatpak / Snap), KernelVault provides native CPack-generated Debian (`.deb`) and tarball packages, accompanied by a dedicated `udev` rule (`99-kvault.rules`) granting console user access via `TAG+="uaccess"`.

#### The Reality Check
Kernel-assisted utilities cannot function inside standard sandboxed runtimes (like Snap or Flatpak) because apparmor/seccomp profiles block direct access to custom `/dev` character devices. Direct package installation ensures that the CLI, Qt GUI, udev rules, man pages, and scalable desktop icons are positioned in standard FHS paths (`/usr/bin`, `/usr/lib/udev/rules.d`, `/usr/share/applications`).

---

## 3. Architecture Decision Records (ADR) Index

| ADR ID | Decision Title | Status | Primary Driver |
| :--- | :--- | :--- | :--- |
| **ADR-001** | Dual-Key PBKDF2 Separation ($K_{\text{enc}} \neq K_{\text{mac}}$) | **Accepted** | NIST SP 800-108 cryptographic hygiene |
| **ADR-002** | Canonical Little-Endian Wire Format | **Accepted** | Cross-architecture binary portability (x86_64 & AArch64) |
| **ADR-003** | Fixed 96-Byte Header Invariant via Reserved Byte Repurposing | **Accepted** | Strict backward compatibility with v1/v2 records |
| **ADR-004** | Anti-Forensic Multi-Pass Source File Shredding | **Accepted** | NIST SP 800-88 defense against forensic data carving |
| **ADR-005** | Native `KVDIR1` Directory Archiving (Zero Subprocesses) | **Accepted** | Shell injection defense & Zip-Slip immunity |
| **ADR-006** | Dual-Engine Fallback (Kernel Driver + Portable C++20) | **Accepted** | Zero-downtime resilience in containerized/unprivileged environments |
| **ADR-007** | Non-Blocking POSIX Advisory Locking (`fcntl(F_SETLK)`) | **Accepted** | Prevention of multi-process writer collisions and corruption |

---

## 4. Architecture Comparison: Toy Script vs. KernelVault

| Dimension | Typical Beginner Utility | KernelVault Implementation |
| :--- | :--- | :--- |
| **Execution Domain** | 100% User Space script / standard library. | **Dual Boundary:** Modern C++20 user space + concurrent C Linux character driver in Ring 0. |
| **Crash Safety** | Directly writes to output file. Crashes cause permanent corruption. | **Atomic Durability:** Writes to hidden `.tmp`, calls `fsync()` to flush hardware storage, and issues atomic `renameat2()`. |
| **Memory Footprint** | $O(N)$ RAM: Allocates entire file in memory. | **$O(1)$ RAM Bounded:** Streaming 64 KiB chunks with stateful incremental `HmacContext`. |
| **Concurrency** | Unhandled. Concurrent runs cause data races. | **Dual Guard:** POSIX `fcntl` advisory locks in userland + per-session `struct kvault_session` in kernel driver. |
| **Memory Security** | Plain string variables, naive `memset()` (stripped by compiler). | **Compiler Barriers & Pinning:** `mlock()` prevents swap paging; `secureZero` and `memzero_explicit` guarantee scrubbing. |
| **Key Hygiene** | Single key reused for encryption and hashing. | **NIST SP 800-108 Separation:** Multi-block PBKDF2 derives distinct $K_{\text{enc}}$ and $K_{\text{mac}}$. |
| **Integrity Model** | Naive decryption; crashes on bad padding. | **Encrypt-then-MAC:** Validates 96-byte header and payload HMAC-SHA256 prior to decryption. |
| **Metadata Preservation** | Discarded; restored files lose `+x` bits and timestamps. | **Full POSIX Preservation:** Restores exact `st_mode` permissions (including executable flags) and `st_mtime`. |
| **Forensic Deletion** | Plain `unlink()`; plaintext persists in unallocated sectors. | **Multi-Pass Shredding:** Overwrites sectors with CSPRNG entropy + zeroes + `fsync()` before unlinking. |
| **Directory Handling** | Single file only or shells out to external `tar`. | **Native Sandbox Archiver:** Recursive directory hierarchy preservation with strict path-traversal sanitization. |
| **Resilience** | Fails if environment prerequisites are missing. | **Graceful Fallback:** Automatically switches to userland software AES if `/dev/kvault` is unavailable. |

---

## 5. Key Takeaways for Technical Reviews & Interviews

When evaluating or discussing KernelVault, consider the following framing:

> *"KernelVault was built not to reinvent file encryption, but to explore the low-level systems engineering contracts required for safe data persistence in Linux. 
> 
> It addresses the problems that arise in real-world systems: how userland and kernel drivers serialize commands across IOCTL boundaries, how database storage engines prevent data corruption through atomic filesystem operations, how concurrency is managed across OS processes and kernel sessions, how memory pinning prevents swap leaks, and how compilers must be instructed to preserve memory hygiene."*
