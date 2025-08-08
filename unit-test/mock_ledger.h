#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// Mock Ledger OS types and functions
typedef int cx_err_t;
#define CX_OK 0
#define CX_CURVE_256K1 1
#define CX_RND_RFC6979 0x80000000
#define CX_LAST 0x40000000

typedef struct {
    uint8_t W[65];
    size_t W_len;
    uint32_t curve;
} cx_ecfp_public_key_t;

typedef struct {
    uint8_t d[32];
    size_t d_len;
    uint32_t curve;
} cx_ecfp_private_key_t;

// Mock functions
#define PRINTF printf
#define PRINTF_BUF(buf, len) do { \
    printf("Buffer[%zu]: ", (size_t)(len)); \
    for (size_t i = 0; i < (size_t)(len); i++) { \
        printf("%02X", ((uint8_t*)(buf))[i]); \
    } \
    printf("\n"); \
} while(0)