#pragma once

#include <stdio.h>
#include <stdlib.h>

// Test framework macros
extern int test_count;
extern int test_passed;
extern int test_failed;

#define TEST_ASSERT(condition, message) do { \
    test_count++; \
    if (condition) { \
        test_passed++; \
        printf("  ✓ %s\n", message); \
    } else { \
        test_failed++; \
        printf("  ✗ %s\n", message); \
        printf("    Assertion failed at %s:%d\n", __FILE__, __LINE__); \
    } \
} while(0)

#define RUN_TEST(test_func) do { \
    printf("Running " #test_func "...\n"); \
    test_func(); \
} while(0)

#define TEST_SUITE_START(name) do { \
    printf("\n=== %s ===\n", name); \
} while(0)

#define TEST_SUITE_END() do { \
    printf("Suite completed.\n"); \
} while(0)

// Test runner functions
void run_bbn_script_tests(void);
void run_bbn_address_tests(void);
void run_bbn_tlv_tests(void);