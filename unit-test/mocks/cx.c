#include "cx.h"
#include <string.h>

// Simple mock implementations
cx_err_t cx_sha256_init(cx_sha256_t *hash) {
    if (!hash) return CX_INVALID_PARAMETER;
    memset(hash, 0, sizeof(cx_sha256_t));
    return CX_OK;
}

cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t len) {
    if (!hash || !in) return CX_INVALID_PARAMETER;
    return CX_OK;
}

cx_err_t cx_hash_final(cx_hash_t *hash, uint8_t *out) {
    if (!hash || !out) return CX_INVALID_PARAMETER;
    memset(out, 0xAA, 32); // SHA256 output size
    return CX_OK;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    if (!hash) return CX_INVALID_PARAMETER;
    
    if (in && in_len > 0) {
        // Mock hash update
    }
    
    if (mode & CX_LAST && out && out_len > 0) {
        // Mock final hash
        memset(out, 0xAA, out_len);
    }
    
    return CX_OK;
}