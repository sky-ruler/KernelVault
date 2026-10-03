/**
 * @file kvault_ioctl.h
 * @brief Shared User/Kernel IOCTL definitions, command macros, and data structures.
 *
 * This header defines the binary interface contract between the user-space
 * kvault storage engine and the kvault Linux kernel device driver.
 * Compatible with both C (Linux Kernel) and modern C++20 user space.
 */

#ifndef KVAULT_IOCTL_H
#define KVAULT_IOCTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
typedef u8 kvault_u8;
typedef u32 kvault_u32;
typedef u64 kvault_u64;
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint8_t kvault_u8;
typedef uint32_t kvault_u32;
typedef uint64_t kvault_u64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Magic character identifier for kvault IOCTL family */
#define KVAULT_IOC_MAGIC 'k'

/** @brief AES-256 key length in bytes */
#define KVAULT_KEY_SIZE 32

/** @brief AES block and IV size in bytes */
#define KVAULT_IV_SIZE 16

/** @brief Maximum single chunk processing size in bytes (64 KiB) */
#define KVAULT_MAX_CHUNK_SIZE (64 * 1024)

/**
 * @enum kvault_cipher_mode
 * @brief Operational mode for the kernel cipher engine
 */
enum kvault_cipher_mode {
    KVAULT_MODE_ENCRYPT = 0,
    KVAULT_MODE_DECRYPT = 1
};

/**
 * @struct kvault_key_param
 * @brief IOCTL payload for passing master key material into kernel space
 */
struct kvault_key_param {
    kvault_u8 key[KVAULT_KEY_SIZE]; /**< 256-bit AES cryptographic key */
    kvault_u32 key_len;             /**< Length of key, must equal 32 */
};

/**
 * @struct kvault_iv_param
 * @brief IOCTL payload for configuring cipher initialization vector
 */
struct kvault_iv_param {
    kvault_u8 iv[KVAULT_IV_SIZE]; /**< 128-bit Initialization Vector */
    kvault_u32 iv_len;            /**< Length of IV, must equal 16 */
};

/**
 * @struct kvault_transform_param
 * @brief IOCTL payload for in-kernel synchronous buffer transformation
 */
struct kvault_transform_param {
    const kvault_u8 *src;         /**< Pointer to user-space input buffer */
    kvault_u8 *dst;               /**< Pointer to user-space output buffer */
    kvault_u32 length;            /**< Buffer length (must be multiple of 16) */
    kvault_u32 mode;              /**< 0 = Encrypt, 1 = Decrypt */
};

/**
 * @struct kvault_status_param
 * @brief IOCTL payload for querying kernel driver health and statistics
 */
struct kvault_status_param {
    kvault_u32 is_key_set;        /**< 1 if key is loaded, 0 otherwise */
    kvault_u32 cipher_mode;       /**< Current active cipher mode */
    kvault_u64 bytes_transformed; /**< Lifetime bytes processed by session */
    kvault_u32 driver_version;    /**< Kernel driver protocol version */
};

/* IOCTL Command Definitions */

/**
 * @def KVAULT_IOCTL_SET_KEY
 * @brief Set the 256-bit AES master key in kernel memory.
 */
#define KVAULT_IOCTL_SET_KEY \
    _IOW(KVAULT_IOC_MAGIC, 1, struct kvault_key_param)

/**
 * @def KVAULT_IOCTL_FLUSH_KEY
 * @brief Wipe kernel key memory immediately using memzero_explicit().
 */
#define KVAULT_IOCTL_FLUSH_KEY \
    _IO(KVAULT_IOC_MAGIC, 2)

/**
 * @def KVAULT_IOCTL_SET_IV
 * @brief Configure initialization vector for subsequent streaming transformations.
 */
#define KVAULT_IOCTL_SET_IV \
    _IOW(KVAULT_IOC_MAGIC, 3, struct kvault_iv_param)

/**
 * @def KVAULT_IOCTL_SET_MODE
 * @brief Select encryption or decryption mode.
 */
#define KVAULT_IOCTL_SET_MODE \
    _IOW(KVAULT_IOC_MAGIC, 4, int)

/**
 * @def KVAULT_IOCTL_GET_STATUS
 * @brief Retrieve kernel driver status, session stats, and key status.
 */
#define KVAULT_IOCTL_GET_STATUS \
    _IOR(KVAULT_IOC_MAGIC, 5, struct kvault_status_param)

/**
 * @def KVAULT_IOCTL_TRANSFORM
 * @brief Synchronously transform a chunk of data in kernel memory.
 */
#define KVAULT_IOCTL_TRANSFORM \
    _IOWR(KVAULT_IOC_MAGIC, 6, struct kvault_transform_param)

#ifdef __cplusplus
}
#endif

#endif /* KVAULT_IOCTL_H */
