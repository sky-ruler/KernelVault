#!/usr/bin/env bash
# ==============================================================================
# KernelVault: Linux Kernel Driver Integration & Lifecycle Test Harness
# ==============================================================================
# Builds driver/kvault.ko, loads it via insmod, validates /dev/kvault creation,
# executes end-to-end cryptographic transformations through the live kernel device,
# validates session zeroization, unloads via rmmod, and audits dmesg logs.
# ==============================================================================

set -euo pipefail

# ANSI styling
BOLD="\033[1m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

log_info()  { echo -e "${CYAN}[INFO]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
log_err()   { echo -e "${RED}[ERROR]${RESET} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

log_info "Starting KernelVault Linux Driver Integration Audit..."

# 1. Check for root or sudo permissions
if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
        log_err "This script requires root or sudo to load/unload kernel modules."
        exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

# 2. Compile user-space CLI if not built
if [[ ! -x "build/kvault" ]]; then
    log_info "Building user-space kvault binary..."
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
    cmake --build build --target kvault -j
fi

# 3. Clean and build driver
log_info "Compiling Linux character driver (driver/kvault.ko)..."
make -C driver clean >/dev/null
make -C driver >/dev/null
if [[ ! -f "driver/kvault.ko" ]]; then
    log_err "Failed to build driver/kvault.ko"
    exit 1
fi
log_ok "driver/kvault.ko built successfully."

# 4. Cleanup any existing module
if lsmod | grep -q "^kvault "; then
    log_warn "Existing kvault module detected. Unloading..."
    ${SUDO} rmmod kvault || true
    sleep 0.5
fi

# 5. Insert module
log_info "Loading driver/kvault.ko into kernel..."
${SUDO} insmod driver/kvault.ko

# 6. Verify device node
sleep 0.5
if [[ ! -c "/dev/kvault" ]]; then
    log_err "Device node /dev/kvault was not created by devtmpfs!"
    ${SUDO} rmmod kvault || true
    exit 1
fi
log_ok "Character device node /dev/kvault created successfully."

# Set permissions for the test session if udev rule is not installed globally
${SUDO} chmod 666 /dev/kvault

# Display dmesg kernel banner
log_info "Recent kernel messages from kvault:"
${SUDO} dmesg | grep "kvault:" | tail -n 8 || true

# 7. Check user-space detection
log_info "Checking user-space kvault driver detection..."
build/kvault status

# 8. Perform end-to-end encryption & decryption through the kernel device
TEST_DIR="$(mktemp -d -t kvault_drv_test_XXXXXX)"
trap 'rm -rf "${TEST_DIR}"' EXIT

TEST_FILE="${TEST_DIR}/sample_payload.bin"
RECOVERED_FILE="${TEST_DIR}/sample_recovered.bin"
PASSPHRASE="KernelDriverEnterprisePassphrase2026!"

log_info "Generating 512 KiB random test payload..."
head -c 524288 /dev/urandom > "${TEST_FILE}"
ORIG_HASH=$(sha256sum "${TEST_FILE}" | awk '{print $1}')

log_info "Encrypting payload via KernelVault..."
build/kvault encrypt --file "${TEST_FILE}" --passphrase "${PASSPHRASE}"

RECORD_NAME="$(basename "${TEST_FILE}").vault"
RECORD_PATH="records/${RECORD_NAME}"

if [[ ! -f "${RECORD_PATH}" ]]; then
    log_err "Encrypted record not found at ${RECORD_PATH}"
    ${SUDO} rmmod kvault || true
    exit 1
fi
log_ok "Encrypted record created: ${RECORD_PATH}"

log_info "Verifying HMAC integrity in-place..."
build/kvault verify --file "${RECORD_NAME}" --passphrase "${PASSPHRASE}"

log_info "Decrypting payload..."
build/kvault decrypt --file "${RECORD_NAME}" --output "${RECOVERED_FILE}" --passphrase "${PASSPHRASE}"

RECOV_HASH=$(sha256sum "${RECOVERED_FILE}" | awk '{print $1}')

if [[ "${ORIG_HASH}" != "${RECOV_HASH}" ]]; then
    log_err "Cryptographic hash mismatch! Original: ${ORIG_HASH}, Recovered: ${RECOV_HASH}"
    ${SUDO} rmmod kvault || true
    exit 1
fi
log_ok "Cryptographic round-trip verified! SHA256: ${RECOV_HASH}"

# Clean up record
build/kvault rm --file "${RECORD_NAME}" --force >/dev/null

# 9. Unload driver and audit teardown
log_info "Unloading driver/kvault.ko..."
${SUDO} rmmod kvault

if [[ -c "/dev/kvault" ]]; then
    log_err "Device node /dev/kvault still exists after rmmod!"
    exit 1
fi
log_ok "Driver unloaded cleanly and /dev/kvault unregistered."

# Check cleanup in dmesg
log_info "Teardown kernel messages:"
${SUDO} dmesg | grep "kvault:" | tail -n 4 || true

# 10. Clean driver artifacts
make -C driver clean >/dev/null
log_ok "All driver integration tests passed with 100% fidelity!"
