# KernelVault: Enterprise Systems & Security Architecture FAQ

This document serves as the comprehensive architectural and systems FAQ for **KernelVault**, answering the critical questions, edge-case behaviors, design trade-offs, and adversarial considerations that enterprise architects, security auditors, and systems programmers evaluate.

---

## Table of Contents
1. [Core Architecture & Philosophy](#1-core-architecture--philosophy)
2. [Cryptographic Design: Why This, Why Not That?](#2-cryptographic-design-why-this-why-not-that)
3. [Memory Hygiene & Defense-in-Depth](#3-memory-hygiene--defense-in-depth)
4. [Linux Kernel Driver & Subsystem Boundary](#4-linux-kernel-driver--subsystem-boundary)
5. [Storage, Concurrency & Crash Durability](#5-storage-concurrency--crash-durability)
6. [Directory Archiving & Path Traversal Mitigations](#6-directory-archiving--path-traversal-mitigations)
7. [Enterprise Operations & Deployment](#7-enterprise-operations--deployment)

---

## 1. Core Architecture & Philosophy

### Q1.1: What exact problem does KernelVault solve compared to standard tools like GPG, OpenSSL CLI, or LUKS?
**KernelVault** is purpose-built to solve the architectural mismatch between whole-disk encryption (LUKS/dm-crypt) and high-level user-space tools (GPG/OpenSSL):
* **Versus LUKS / dm-crypt:** LUKS operates at the block-device level (`ring 0`). Once a LUKS container is unlocked, all decrypted files are exposed in plaintext to any process with read permissions. KernelVault provides **application-level, per-record isolation** where sensitive assets remain encrypted at rest and in storage even on an unlocked machine.
* **Versus OpenSSL CLI / GPG:** OpenSSL CLI scripts and GPG wrappers frequently spawn external subprocesses (`execve`), pass secrets via shell arguments or intermediate files, require massive runtime memory spikes for large archives, and lack kernel-space hardware acceleration with session isolation. KernelVault is a single, zero-subprocess, native C++20 and C system with deterministic memory pinning, atomic crash consistency, and in-kernel hardware acceleration.

### Q1.2: Why is KernelVault strictly Linux-only? Why reject Windows or macOS?
Enterprise security requires deep integration with OS-specific memory and hardware primitives. Cross-platform abstractions (like portable runtimes) invariably reduce security to the lowest common denominator:
1. **Memory Pinning:** We rely on Linux `mlock(2)` and `madvise(MADV_DONTDUMP)` to guarantee that sensitive cryptographic key material is never written to disk swap space or exposed in user-space core dumps.
2. **Kernel Driver Acceleration:** KernelVault interfaces directly with the **Linux Kernel Crypto API** (`crypto_alloc_skcipher`) via a custom character device driver (`/dev/kvault`).
3. **Advisory Locking:** We enforce non-blocking POSIX `fcntl(F_SETLK)` locking semantics native to the Linux VFS layer.
4. **POSIX Metadata Preservation:** Full preservation of 32-bit `st_mode` permissions and nanosecond-resolution epoch modification timestamps.

Attempting to abstract these away creates subtle timing vulnerabilities and memory leakages on non-POSIX operating systems.

---

## 2. Cryptographic Design: Why This, Why Not That?

### Q2.1: Why AES-256-CBC with HMAC-SHA256 instead of AES-256-GCM?
This is the most common question in cryptographic reviews. While AES-GCM (an Authenticated Encryption with Associated Data / AEAD mode) is popular, AES-256-CBC paired with HMAC-SHA256 under the **Encrypt-then-MAC (EtM)** paradigm was chosen for definitive systems reasons:

| Evaluation Criteria | AES-256-GCM | AES-256-CBC + HMAC-SHA256 (KernelVault) |
| :--- | :--- | :--- |
| **Nonce-Reuse Blast Radius** | **Catastrophic Failure.** A single nonce reuse completely destroys the GHASH authentication key, allowing arbitrary forgery of all subsequent records. | **Graceful Degradation.** Reusing an IV in CBC mode reveals only whether two plaintexts share a common prefix block; it *never* compromises the key or allows forgery. |
| **Streaming Integrity Validation** | GCM requires verifying the authentication tag at the *end* of the stream. If memory is bounded, user-space must either buffer the entire plaintext in RAM or commit unverified plaintext to disk. | **Strict Stream Authentication.** Under Encrypt-then-MAC, the ciphertext is authenticated *before* decryption buffers are ever touched. |
| **Kernel Driver Portability** | In-kernel GCM AEAD transformation buffers require complex scatterlist association for out-of-band tags (`AEAD_REQ`). | CBC cipher transforms align directly with synchronous chunked scatterlists (`crypto_skcipher`), minimizing driver kernel overhead. |
| **Standard Consensus** | Recommended for high-speed network protocols with counter management. | Formally proven secure by Hugo Krawczyk (2001) as the most resilient authenticated encryption construction. |

### Q2.2: Why does Version 3 enforce Dual-Key Derivation ($K_{\text{enc}} \neq K_{\text{mac}}$)?
In cryptographic protocols, **using the same key for multiple cryptographic primitives violates key-separation hygiene**. 
* In KernelVault v1/v2, deriving a single key and using it for both AES encryption and HMAC authentication could theoretically allow cross-protocol interactions where internal cipher states leak information about authentication tags.
* In **KernelVault v3**, we execute RFC 2898 multi-block PBKDF2:
  $$\text{Block 1} = \text{PBKDF2}(P, S, 100000, 1) \longrightarrow K_{\text{enc}} \quad (32\text{ bytes for AES-256})$$
  $$\text{Block 2} = \text{PBKDF2}(P, S, 100000, 2) \longrightarrow K_{\text{mac}} \quad (32\text{ bytes for HMAC-SHA256})$$
This guarantees that $K_{\text{enc}}$ and $K_{\text{mac}}$ are cryptographically orthogonal ($H(K_{\text{enc}}) \neq H(K_{\text{mac}})$). Even if an adversary were to somehow recover $K_{\text{mac}}$, they cannot decrypt the ciphertext.

### Q2.3: Why PBKDF2-HMAC-SHA256 with 100,000 rounds instead of Argon2id?
1. **Zero-Dependency Portability:** PBKDF2-HMAC-SHA256 is mathematically self-contained and implemented directly in clean C++20 without requiring heavy external shared libraries (`libargon2`), eliminating supply-chain attack vectors.
2. **Predictable Memory Footprint:** Argon2id requires 64–128 MiB of dedicated RAM per derivation. In server environments running concurrent vault operations across dozens of worker threads, Argon2id can trigger out-of-memory (OOM) kernel panics. PBKDF2 uses bounded stack memory while achieving high iteration hardness (100,000 rounds = ~1.4 seconds of compute per derivation).
3. **NIST Compliance:** PBKDF2-HMAC-SHA256 conforms strictly to NIST SP 800-132 recommendations.

### Q2.4: Why Little-Endian canonical wire format?
Big-endian wire formats (historically "network byte order") require host-to-network (`htons`/`htonl`) conversion on x86_64 systems. Because **99.9% of modern Linux servers and workstations run little-endian microarchitectures (x86_64, aarch64)**, little-endian serialization:
- Eliminates CPU endianness byte-swapping instruction overhead.
- Guarantees byte-level portability if vault files are moved between x86_64 and ARM64 servers.
- Is validated at compile-time via `static_assert(std::endian::native == std::endian::little)`.

---

## 3. Memory Hygiene & Defense-in-Depth

### Q3.1: How does KernelVault prevent cryptographic keys from leaking into swap space?
Standard user-space memory allocations (`malloc`, `new`, `std::vector`) can be swapped out to disk by the Linux virtual memory manager (`kswapd`) whenever the machine experiences RAM pressure. If keys are swapped out, sensitive plaintext remains etched on unencrypted swap partitions indefinitely.
* **The Solution:** We implemented [`PinnedMemory<N>`](../include/PinnedMemory.hpp).
* Upon allocation, `PinnedMemory` calls:
  ```cpp
  ::mlock(m_buffer.data(), N);
  ::madvise(m_buffer.data(), N, MADV_DONTDUMP);
  ```
* `mlock(2)` locks the memory pages into physical RAM, forbidding the kernel from paging them to swap.
* `madvise(MADV_DONTDUMP)` instructs the Linux kernel to exclude these memory pages from user-space core dump files if the application crashes or receives `SIGSEGV`.

### Q3.2: Why not just use `memset()` to wipe memory? Why compiler memory barriers?
Modern optimizing compilers (such as GCC 14/15 or Clang 18 with `-O2` or `-O3`) perform **Dead-Store Elimination (DSE)**. If a memory buffer is not read again before it is freed or goes out of scope, the compiler treats the `memset()` as redundant dead code and optimizes it away entirely!
* **The Solution:** We implemented [`KeyDerivation::secureZero()`](../src/KeyDerivation.cpp):
  ```cpp
  void KeyDerivation::secureZero(void* ptr, size_t length) noexcept {
      volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
      while (length--) {
          *p++ = 0;
      }
      asm volatile("" : : "r"(ptr) : "memory");
  }
  ```
* The `volatile` pointer forces the CPU to write zeroes to memory sequentially.
* The inline assembly statement `asm volatile("" : : "r"(ptr) : "memory")` acts as a compiler memory barrier, informing the optimizer that arbitrary external reads depend on this memory, making dead-store elimination impossible.
* In kernel space, we invoke `memzero_explicit()`, which is the Linux kernel's standard defense against dead-store elimination.

### Q3.3: How are passwords protected from `ps aux` and `/proc/<pid>/cmdline`?
When a user passes `--key <passphrase>` via CLI, that string resides in the program's `argv` array in user-space address space. On Linux, any other user on the machine can read `/proc/<pid>/cmdline` or execute `ps aux` and inspect the plain argument.
* **The Solution:** Immediately upon parsing `argv`, KernelVault invokes:
  ```cpp
  std::memset(argv[i], 'x', std::strlen(argv[i]));
  ```
* The memory address hosting the argument in `/proc/<pid>/cmdline` is overwritten with mask characters within microseconds of process launch.
* Furthermore, we provide **interactive masked input** (using POSIX `termios` with `ECHO` disabled) and pipeline input (`--key-stdin`), which bypass `argv` entirely.

---

## 4. Linux Kernel Driver & Subsystem Boundary

### Q4.1: Why implement a custom Linux character driver instead of using user-space crypto libraries?
1. **Architectural Separation of Privilege:** The master encryption keys can be loaded into in-kernel session memory (`ring 0`). User-space processes perform transformations by passing ciphertext buffers across `ioctl`, without keeping persistent master keys in user-space heap memory.
2. **Hardware Acceleration via Kernel Crypto API:** The driver leverages the Linux Kernel Crypto subsystem (`crypto_alloc_skcipher("cbc(aes)", 0, 0)`), which automatically binds to native hardware cryptographic engines (Intel AES-NI, AMD Cryptographic Coprocessor, ARM Cryptography Extensions) directly at the kernel driver layer.
3. **Session Isolation:** Multiple independent user-space processes (or threads) can open `/dev/kvault` simultaneously. Each open file descriptor allocates a distinct `struct kvault_session` guarded by its own `mutex`, preventing cross-process key contamination.

### Q4.2: Why is the driver optional? What happens if `/dev/kvault` is not loaded?
KernelVault implements **graceful degradation**:
- Upon initialization, `VaultManager` calls `openKernelDevice()`.
- If `/dev/kvault` exists and can be opened, hardware-assisted kernel transformations are engaged.
- If the driver is not installed (e.g. on cloud VPS instances without kernel header build rights, container environments, or standard user accounts without udev access), `VaultManager` automatically falls back to its built-in, constant-time `SoftwareAes256` cipher engine.
- Vault files encrypted by the kernel driver and the software fallback are **100% binary identical and interoperable**.

### Q4.3: How does the driver prevent kernel memory leaks and dangling sessions?
- Every session allocated in `kvault_open` via `kzalloc()` is tracked in the file's `file->private_data`.
- In `kvault_release`, the driver:
  1. Acquires the session mutex.
  2. Invokes `memzero_explicit()` to wipe all session key and IV memory.
  3. Frees the crypto transform (`crypto_free_skcipher(sess->tfm)`).
  4. Releases the mutex and frees the session structure with `kfree()`.
- This ensures zero memory leaks upon process exit or abort.

---

## 5. Storage, Concurrency & Crash Durability

### Q5.1: How does KernelVault guarantee crash consistency if power is lost mid-encryption?
If a storage tool writes directly to the destination file and the system loses power or crashes halfway through, the original file is destroyed and the encrypted file is left in a corrupted, half-written state.
* **The Solution:** We implemented [`AtomicFileWriter`](../include/AtomicFileWriter.hpp):
  1. Data is written to an isolated staging file: `<destination>.tmp.<pid>.<random>`.
  2. Data is written in streaming 64 KiB chunks.
  3. Before finalizing, `AtomicFileWriter::commit()` issues `::fsync(fd)`, flushing the OS page cache to physical disk platters/NAND flash.
  4. The file is atomically moved to its final path via `::rename(tmpPath, destPath)`.
* Under POSIX filesystem specifications, `rename(2)` is an **atomic transaction**. The destination file either points completely to the old version or completely to the new version; it can *never* be observed in a partially written or corrupted state.

### Q5.2: How does KernelVault prevent race conditions between concurrent readers and writers?
* **The Solution:** We implemented non-blocking POSIX advisory file locking via [`FileLock`](../include/FileLock.hpp).
* Every vault record `records/file.txt.enc` is associated with an exclusive lockfile `locks/file.txt.lock`.
* When encrypting or modifying a record, KernelVault requests an exclusive non-blocking lock (`F_SETLK` with `F_WRLCK`). If another process is currently writing to that record, `acquireExclusive()` immediately fails with a descriptive collision error rather than hanging or corrupting data.
* Stale locks left by terminated or crashed processes are automatically detected and garbage-collected via PID liveliness checks (`kill(pid, 0)`).

---

## 6. Directory Archiving & Path Traversal Mitigations

### Q6.1: Why not just call `tar -czf` via subprocess to archive directories?
Spawning external tools via `system()` or `fork()`/`execve()` introduces severe enterprise security liabilities:
1. **Subprocess Injection:** Malicious file paths with shell meta-characters (`;`, `|`, `&`, `$()`) can cause arbitrary command execution if passed to a shell.
2. **Uncontrolled Memory & Disk Footprint:** `tar` typically creates intermediate unencrypted tarball archives on `/tmp`, writing plaintext to disk before encryption occurs!
3. **External Dependencies:** The host might not have `tar`, or might have incompatible BSD vs GNU `tar` implementations.
* **The Solution:** We created the native, self-contained **`KVDIR1` binary format**. It walks directory trees using C++20 `std::filesystem::recursive_directory_iterator`, streaming file metadata, paths, permissions, and bytes directly into the encryption engine in a single pass without ever writing an unencrypted archive to disk.

### Q6.2: How does KernelVault prevent Zip-Slip / Tar-Slip directory traversal attacks?
If an attacker creates a malicious archive containing entries like `../../../../etc/shadow` or `/home/user/.bashrc`, extracting it could overwrite critical system files.
* **The Solution:** In `VaultManager::decryptDirectory`, every path extracted from the binary pack undergoes strict 3-stage validation before any file or directory is touched:
  1. **Leading Slashes Rejected:** Any entry beginning with `/` or `\\` is immediately rejected.
  2. **Traversal Tokens Forbidden:** Any path segment containing `..` or empty tokens throws a security exception.
  3. **Lexical Canonicalization:** The combined destination path is resolved and validated:
     ```cpp
     auto dest = (destDir / cleanRel).lexically_normal();
     // Verified to ensure dest starts strictly with destDir
     ```

---

## 7. Enterprise Operations & Deployment

### Q7.1: What are the exact requirements to run KernelVault in production?
- **Host OS:** Linux Kernel 6.0+ (Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12, RHEL 9+, Arch Linux).
- **Toolchain:** GCC 12+ or Clang 15+ (C++20 required).
- **Libraries:**
  - `libstdc++6` (>= 12)
  - `libc6` (>= 2.34)
  - `qt6-base-dev` (optional, only required if compiling the desktop GUI)
  - `kmod` and `linux-headers-$(uname -r)` (optional, only required if compiling the kernel driver)

### Q7.2: Can KernelVault be deployed in Docker or Kubernetes containers?
Yes:
- The user-space CLI and GUI run completely unprivileged inside standard Linux containers.
- If the host machine has `/dev/kvault` loaded, the device node can be passed to the container via `--device /dev/kvault:/dev/kvault`.
- If the container is unprivileged and has no device access, KernelVault's automatic fallback immediately engages and runs with full software cryptographic acceleration.
