#ifndef UX_H
#define UX_H

#include <stdint.h>

// Mock UX definitions for unit tests
typedef struct {
    uint32_t dummy;
} ux_state_t;

// Mock UX functions
void ux_flow_init(int flow_index, void* step, void* cb);

#endif