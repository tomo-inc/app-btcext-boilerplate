#include "mock_printf.h"
#include <stdio.h>
#include <stdarg.h>

// Mock PRINTF function
int PRINTF(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = vprintf(format, args);
    va_end(args);
    return result;
}

// Mock PRINTF_BUF function
void PRINTF_BUF(const uint8_t *buffer, size_t length) {
    printf("Buffer[%zu]: ", length);
    for (size_t i = 0; i < length; i++) {
        printf("%02X", buffer[i]);
        if (i < length - 1) printf(" ");
    }
    printf("\n");
}