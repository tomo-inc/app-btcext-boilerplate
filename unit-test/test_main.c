#include <stdio.h>
#include <stdlib.h>

#include "test_framework.h"

// Global test counters
int test_count = 0;
int test_passed = 0;
int test_failed = 0;

int main(void) {
    printf("BBN Unit Tests\n");
    printf("==============\n");
    
    // Run all test suites
    run_bbn_script_tests();
    run_bbn_address_tests();
    // run_bbn_tlv_tests();  // Add when implemented
    
    // Print summary
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", test_count);
    printf("Passed: %d\n", test_passed);
    printf("Failed: %d\n", test_failed);
    
    if (test_failed > 0) {
        printf("\n❌ Some tests failed!\n");
        return EXIT_FAILURE;
    } else {
        printf("\n✅ All tests passed!\n");
        return EXIT_SUCCESS;
    }
}