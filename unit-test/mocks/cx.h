#ifndef CX_H
#define CX_H

#include <stdint.h>
#include <stddef.h>

// Mock Ledger crypto constants
#define CX_OK 0
#define CX_INVALID_PARAMETER 1
#define CX_LAST 1
#define CX_SHA256_SIZE 32

typedef enum {
    CX_ERR_OK = 0,
    CX_ERR_INVALID_PARAMETER = 1
} cx_err_t;

// Mock hash context
typedef struct {
    uint8_t dummy[64];
} cx_hash_t;

typedef struct {
    cx_hash_t header;
} cx_sha256_t;

// Mock function declarations
cx_err_t cx_sha256_init(cx_sha256_t *hash);
cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t len);
cx_err_t cx_hash_final(cx_hash_t *hash, uint8_t *out);
cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

#endif