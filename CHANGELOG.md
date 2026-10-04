# Changelog

All notable changes to the **KernelVault** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.1] - 2026-10-04

### Fixed
- **Packaging Dependencies:** Added `libqt6widgets6 | libqt6widgets6t64` to `CPACK_DEBIAN_PACKAGE_DEPENDS` so that installing the `.deb` package automatically pulls in the Qt6 runtime libraries required by `kvault-gui`.
- **Desktop Entry Categories:** Standardized `packaging/kvault.desktop` categories to `Utility;Security;System;` strictly adhering to the FreeDesktop specification.
- **Compiler Warning Guard:** Prevented GCC 15 `-Wfree-nonheap-object` false positive during PBKDF2 salt vector construction.

## [3.0.0] - 2026-10-04

### Added
- **Empirical Hardware Benchmarking (`kvault bench`):** Measures key derivation iteration rate and streaming throughput across 64 KiB chunks for AES-256-CBC, HMAC-SHA256, and full Encrypt-then-MAC pipelines.
- **Directory Hierarchy Archiving (`KVDIR1`):** Pack and restore recursive directory trees with strict path sanitization preventing zip-slip path traversal.
- **POSIX Metadata Preservation:** Preserves original file permissions (`chmod`) and modification timestamps (`utimensat`) packed inside the 96-byte `VaultHeader`.
- **In-Place Cryptographic Audit (`kvault verify`):** Streamed HMAC-SHA256 integrity audits directly against encrypted records without disk extraction footprints.
- **Tabular Record Inventory (`kvault list`):** Real-time CLI table showing plaintext size, encrypted size, POSIX modes, modification timestamps, and advisory lock state.
- **Safe Record Deletion (`kvault rm`):** Non-blocking advisory lock synchronization for removing stored records and associated locks.
- **Anti-Forensic File Shredding:** Secure source file wiping (`--shred` / `--wipe`) utilizing CSPRNG entropy (`getrandom`), zeroization, and `fsync()`.
- **Batch & Wildcard Expansion:** Single-pass multi-file encryption and decryption with POSIX globbing (`*.txt`, `*.pdf`) and masked single-pass passphrase caching.
- **Modernized Qt6 Desktop GUI:** 3-tab native interface (Encrypt, Decrypt, Inventory) with double-click record inspection, in-place HMAC verification, and folder tree restoration.
- **Enterprise GitHub Infrastructure:** Issue forms, PR review templates, CodeQL security scanning, Dependabot, CODEOWNERS, and packaging automation.
- **Packaging:** Debian `.deb` and `.tar.gz` distribution generators via CPack, standard `.desktop` entry, and SVG vector icon.

### Changed
- **Dual-Key Derivation Invariant:** Replaced single derived key with RFC 2898 multi-block dual keys ($K_{\text{enc}} \neq K_{\text{mac}}$).
- **Canonical Endianness Wire Format:** Explicit Little-Endian encoding across all header integer fields.
- **Header Structure:** Repurposed 8 reserved bytes in `VaultHeader` into `uint32_t posix_mode` and `uint32_t mtime_epoch` while preserving the exact 96-byte size invariant (`static_assert(sizeof(VaultHeader) == 96)`).

### Fixed
- Fixed integer promotion in Galois field multiplication (`xtime`, `multiply`) to guarantee zero compiler warnings under GCC 15 `-Wconversion`.
- Eliminated all memory leaks, heap corruptions, and undefined behavior verified under AddressSanitizer and UndefinedBehaviorSanitizer.

---

## [2.0.0] - 2026-10-02

### Added
- **Authenticated Header Protection:** Extended HMAC-SHA256 to cover the record header with zeroed MAC tag, preventing unauthenticated header tampering.
- **Linux Character Device Driver (`/dev/kvault`):** Dedicated character driver bridging user-space to Linux Kernel Crypto API with session isolation.
- **Advisory POSIX File Locking:** Non-blocking `fcntl` locking (`F_SETLK`) preventing concurrent writer collisions and corruption.
- **Atomic File Writing:** Crash-consistent staging to `.tmp` files with `fsync()` and atomic `rename()`.

---

## [1.0.0] - 2026-09-28

### Added
- Initial proof-of-concept single-file encryption demonstrator.
- User-space AES-256-CBC software cipher fallback.
- PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations.
- Basic CLI commands (`init`, `encrypt`, `decrypt`, `status`).
