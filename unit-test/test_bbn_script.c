#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Include test framework
#include "test_framework.h"

// Include mocks
#include "mocks/mock_crypto.h"
#include "mocks/mock_printf.h"

// Include modules to test
#include "bbn_script.h"
#include "bbn_data.h"

static void setup_test_data(void) {
    // Setup test BBN data
    g_bbn_data.has_cov_key_list = true;
    g_bbn_data.cov_key_count = 2;
    g_bbn_data.cov_quorum = 2;
    g_bbn_data.has_cov_quorum = true;
    
    // Mock covenant public keys
    memset(g_bbn_data.cov_keys[0], 0x11, 32);
    memset(g_bbn_data.cov_keys[1], 0x22, 32);
    
    // Setup finality providers
    g_bbn_data.has_fp_list = true;
    g_bbn_data.fp_count = 1;
    memset(g_bbn_data.fp_keys[0], 0x33, 32);
    
    // Setup timelock
    g_bbn_data.has_timelock = true;
    g_bbn_data.timelock = 1000;
    
    // Setup staker key
    g_bbn_data.has_staker_pk = true;
    memset(g_bbn_data.staker_pk, 0x44, 32);
}

static void test_compute_bbn_leafhash_slashing(void) {
    setup_test_data();
    
    uint8_t leafhash[32];
    bool result = compute_bbn_leafhash_slashing(leafhash);
    
    TEST_ASSERT(result == true, "compute_bbn_leafhash_slashing should succeed");
    
    // Check hash is not all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (leafhash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!all_zero, "leafhash should not be all zeros");
}

static void test_compute_bbn_leafhash_unbonding(void) {
    setup_test_data();
    
    uint8_t leafhash[32];
    bool result = compute_bbn_leafhash_unbonding(leafhash);
    
    TEST_ASSERT(result == true, "compute_bbn_leafhash_unbonding should succeed");
}

static void test_compute_bbn_leafhash_timelock(void) {
    setup_test_data();
    
    uint8_t leafhash[32];
    bool result = compute_bbn_leafhash_timelock(leafhash);
    
    TEST_ASSERT(result == true, "compute_bbn_leafhash_timelock should succeed");
}

static void test_compute_bbn_merkle_root(void) {
    setup_test_data();
    
    uint8_t roothash[32];
    compute_bbn_merkle_root(roothash);
    
    // Check hash is not all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (roothash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!all_zero, "merkle root should not be all zeros");
}

void run_bbn_script_tests(void) {
    TEST_SUITE_START("BBN Script Tests");
    
    RUN_TEST(test_compute_bbn_leafhash_slashing);
    RUN_TEST(test_compute_bbn_leafhash_unbonding);
    RUN_TEST(test_compute_bbn_leafhash_timelock);
    RUN_TEST(test_compute_bbn_merkle_root);
    
    TEST_SUITE_END();
}