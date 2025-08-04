#pragma once

#include <stdint.h>
#include <stddef.h>

// Mock printf functions
int PRINTF(const char *format, ...);
void PRINTF_BUF(const uint8_t *buffer, size_t length);