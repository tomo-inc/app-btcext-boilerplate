#ifndef OS_H
#define OS_H

#include <stdint.h>
#include <stddef.h>

// Mock OS types and constants
#define OS_OK 0
#define OS_ERROR 1

// 移除这个定义，避免与 bitcoin_app_base 冲突
// #define MAX_OUTPUT_SCRIPTPUBKEY_LEN 34

typedef uint32_t os_err_t;

#endif