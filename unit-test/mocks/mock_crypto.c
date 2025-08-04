#include "mock_crypto.h"
#include <string.h>

// Mock crypto_tr_tweak_pubkey
int crypto_tr_tweak_pubkey(const uint8_t *pubkey, 
                          const uint8_t *tweak, 
                          size_t tweak_len,
                          uint8_t *parity, 
                          uint8_t *tweaked_pubkey) {
    // Simple mock: XOR pubkey with tweak
    *parity = 0;
    
    for (size_t i = 0; i < 32; i++) {  // 修改这里，使用 size_t
        tweaked_pubkey[i] = pubkey[i] ^ (i < tweak_len ? tweak[i] : 0);
    }
    
    return 0;
}

// Mock hash functions
void crypto_hash_sha256(const uint8_t *in, size_t in_len, uint8_t *out) {
    // Simple mock hash - just copy and pad
    memset(out, 0, 32);
    size_t copy_len = (in_len > 32) ? 32 : in_len;
    memcpy(out, in, copy_len);
    
    // Add some "randomness"
    for (size_t i = 0; i < 32; i++) {  // 修改这里，使用 size_t
        out[i] ^= (uint8_t)((i + in_len) & 0xFF);
    }
}

void crypto_hash_sha256_two(const uint8_t *in1, size_t in1_len,
                           const uint8_t *in2, size_t in2_len,
                           uint8_t *out) {
    uint8_t combined[64];
    memset(combined, 0, sizeof(combined));
    
    size_t pos = 0;
    if (in1_len > 0 && pos < 64) {
        size_t copy1 = (in1_len > 64 - pos) ? 64 - pos : in1_len;
        memcpy(combined + pos, in1, copy1);
        pos += copy1;
    }
    
    if (in2_len > 0 && pos < 64) {
        size_t copy2 = (in2_len > 64 - pos) ? 64 - pos : in2_len;
        memcpy(combined + pos, in2, copy2);
    }
    
    crypto_hash_sha256(combined, 64, out);
}