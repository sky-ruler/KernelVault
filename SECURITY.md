# Security Policy & Vulnerability Disclosure

KernelVault is a security-critical cryptographic storage and Linux kernel driver subsystem. We take the security and integrity of our codebase, memory management, and cryptographic primitives with the highest priority.

---

## Supported Versions

Security updates, hotfixes, and cryptographic review patches are actively maintained for the following versions:

| Version | Status | Security Support Level | Cryptographic Key Invariant |
| :--- | :--- | :--- | :--- |
| **3.0.x** | **Active / Current** | **Full Security & Bug Fixes** | Dual Keys ($K_{\text{enc}} \neq K_{\text{mac}}$), Little-Endian 96-byte header |
| **2.0.x** | Deprecated | Critical Security Fixes Only | Single Derived Key, Authenticated Header |
| **1.0.x** | End-of-Life | Vulnerability Alerts Only | Unauthenticated Header (Deprecated) |

---

## Reporting a Security Vulnerability

> [!CAUTION]
> **Please DO NOT file public GitHub issues for security vulnerabilities or zero-day exploits.**
> Public disclosure exposes users before a coordinated mitigation can be delivered.

If you believe you have discovered a vulnerability, memory disclosure, side-channel leakage, or kernel driver flaw in KernelVault, please report it through one of the following confidential channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**
   - Navigate to the **Security** tab of the repository on GitHub.
   - Click **Advisories** &rarr; **Report a vulnerability**.
   - This opens an encrypted, private communication channel directly with the maintainers.

2. **Direct Security Email:**
   - Email: **`skyruler3281@gmail.com`**
   - Subject line: `[SECURITY] Vulnerability Report: KernelVault - <Component>`

### What to Include in Your Report
To help us triage and remediate the issue rapidly, please include:
- **Component affected:** (e.g., Linux kernel module `driver/kvault_module.c`, Key derivation `KeyDerivation.cpp`, Directory archive `VaultManager.cpp`, Memory pinning `PinnedMemory.hpp`).
- **Proof-of-Concept (PoC):** Minimal reproducible script or test case triggering the fault.
- **Environment:** Linux kernel version (`uname -r`), CPU architecture, compiler version (`gcc --version`), and distro.
- **Sanitizer output:** If applicable, AddressSanitizer (ASan), LeakSanitizer (LSan), or UndefinedBehaviorSanitizer (UBSan) crash logs.
- **Assessment of impact:** Potential consequences (e.g., privilege escalation, plaintext key extraction from RAM, denial-of-service, integrity tag bypass).

---

## Response & Disclosure SLA

We adhere to the principles of **Coordinated Vulnerability Disclosure (CVD)**:

* **Initial Response:** Within **48 hours**, acknowledging receipt and initial triage.
* **Status Updates:** Every **7 business days**, providing remediation progress.
* **Patch Development:** Critical flaws are prioritized with a target patch turnaround of **14 days**.
* **Public Disclosure:** Following patch release and verification, a CVE will be assigned (if applicable) and a detailed Security Advisory published.

---

## Cryptographic & Kernel Threat Model

KernelVault is engineered under an explicit threat model:

1. **Data-at-Rest Protection:** If the underlying storage medium is stolen or imaged, plaintext content and directory structure remain protected under AES-256-CBC and PBKDF2-HMAC-SHA256.
2. **Integrity Enforcement:** Any unauthorized modification of the 96-byte header or ciphertext body causes immediate rejection before decryption buffers are populated (preventing CBC padding-oracle attacks).
3. **Memory Hygiene Barrier:** Cryptographic keys are locked in unswappable RAM (`mlock(2)`) and wiped with compiler-barrier zeroization (`secureZero` / `memzero_explicit`) upon process exit or session closure.
4. **Out-of-Scope:** Compromised kernel root space (`ring 0`) or hardware compromise (e.g., physical cold-boot attack on unencrypted DRAM) is outside the user-space threat boundary, though kernel driver isolation mitigates user-space crash blast radius.
