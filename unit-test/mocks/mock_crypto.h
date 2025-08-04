#pragma once

#include <stdint.h>
#include <stddef.h>

// Mock crypto functions
int crypto_tr_tweak_pubkey(const uint8_t *pubkey, 
                          const uint8_t *tweak, 
                          size_t tweak_len,
                          uint8_t *parity, 
                          uint8_t *tweaked_pubkey);

void crypto_hash_sha256(const uint8_t *in, size_t in_len, uint8_t *out);

void crypto_hash_sha256_two(const uint8_t *in1, size_t in1_len,
                           const uint8_t *in2, size_t in2_len,
                           uint8_t *out);