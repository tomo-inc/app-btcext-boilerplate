#ifndef MOCK_TYPES_H
#define MOCK_TYPES_H

#include <stdint.h>
#include <stdbool.h>

// Mock sign_psbt_state_t structure
typedef struct {
    struct {
        uint8_t output_scripts[2][34];
        size_t output_script_lengths[2];
        uint64_t total_amount;
    } outputs;
    uint64_t inputs_total_amount;
} sign_psbt_state_t;

#endif