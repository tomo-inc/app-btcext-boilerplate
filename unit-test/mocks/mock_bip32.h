#pragma once

#include <stdint.h>

// Mock types
typedef struct {
    uint8_t compressed_pubkey[33];
    uint8_t chain_code[32];
} serialized_extended_pubkey_t;

// Mock BIP32 functions
int bip32_CKDpub(const serialized_extended_pubkey_t *parent, 
                 uint32_t index,
                 serialized_extended_pubkey_t *child, 
                 uint8_t *chain_code);

uint64_t read_u64_le(const uint8_t *buffer, uint32_t offset);