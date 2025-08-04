#include "mock_bip32.h"
#include <string.h>

// Mock BIP32 functions
int bip32_CKDpub(const serialized_extended_pubkey_t *parent, 
                 uint32_t index,
                 serialized_extended_pubkey_t *child, 
                 uint8_t *chain_code) {
    // Simple mock derivation
    memcpy(child, parent, sizeof(serialized_extended_pubkey_t));
    
    // Modify the public key slightly based on index
    child->compressed_pubkey[31] ^= (index & 0xFF);
    child->compressed_pubkey[30] ^= ((index >> 8) & 0xFF);
    
    return 0;
}

uint64_t read_u64_le(const uint8_t *buffer, uint32_t offset) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((uint64_t)buffer[offset + i]) << (8 * i);
    }
    return result;
}