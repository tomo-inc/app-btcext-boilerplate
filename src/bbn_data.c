#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../bitcoin_app_base/src/common/merkle.h"
#include "bbn_def.h"
#include "bbn_data.h"

bbn_data_t g_bbn_data;
bbn_pub_t g_bbn_pub;

// 将g_bbn_data中的公钥数据缓存到g_bbn_pub中
void bbn_buffer_pubkeys(void) {
    PRINTF("Buffering public keys\n");
    g_bbn_pub.fp_count = g_bbn_data.fp_count;
    for (uint32_t i = 0; i < g_bbn_data.fp_count && i < MAX_FP_COUNT; i++) {
        memcpy(g_bbn_pub.fp_pub[i], g_bbn_data.fp_list[i], 32);
    }

    g_bbn_pub.cov_count = g_bbn_data.cov_key_count;
    for (uint32_t i = 0; i < g_bbn_data.cov_key_count && i < MAX_COV_KEY_COUNT; i++) {
        memcpy(g_bbn_pub.cov_pub[i], g_bbn_data.cov_key_list[i], 32);
    }

    g_bbn_pub.cov_quorum = g_bbn_data.cov_quorum;
}

// 比较g_bbn_pub和g_bbn_data中的公钥数据是否一致
bool bbn_compare_pubkeys(void) {
    if (g_bbn_pub.fp_count != g_bbn_data.fp_count) {
        PRINTF("Finality provider count mismatch\n");
        PRINTF("Buffered: %d, Current: %d\n", g_bbn_pub.fp_count, g_bbn_data.fp_count);
        bbn_reset_buffer();
        return false;
    }
    if (g_bbn_pub.cov_count != g_bbn_data.cov_key_count) {
        PRINTF("Covenant key count mismatch\n");
        PRINTF("Buffered: %d, Current: %d\n", g_bbn_pub.cov_count, g_bbn_data.cov_key_count);
        bbn_reset_buffer();
        return false;
    }
    if (g_bbn_pub.cov_quorum != g_bbn_data.cov_quorum) {
        PRINTF("Covenant quorum mismatch\n");
        PRINTF("Buffered: %d, Current: %d\n", g_bbn_pub.cov_quorum, g_bbn_data.cov_quorum);
        bbn_reset_buffer();
        return false;
    }

    for (uint32_t i = 0; i < g_bbn_pub.fp_count; i++) {
        if (memcmp(g_bbn_pub.fp_pub[i], g_bbn_data.fp_list[i], 32) != 0) {
            PRINTF("Finality provider public key mismatch at index %d\n", i);
            PRINTF_BUF(g_bbn_pub.fp_pub[i], 32);
            PRINTF_BUF(g_bbn_data.fp_list[i], 32);
            bbn_reset_buffer();
            return false;
        }
    }

    for (uint32_t i = 0; i < g_bbn_pub.cov_count; i++) {
        if (memcmp(g_bbn_pub.cov_pub[i], g_bbn_data.cov_key_list[i], 32) != 0) {
            PRINTF("Covenant public key mismatch at index %d\n", i);
            PRINTF_BUF(g_bbn_pub.cov_pub[i], 32);
            PRINTF_BUF(g_bbn_data.cov_key_list[i], 32);
            bbn_reset_buffer();
            return false;
        }
    }
    PRINTF("Public keys match the buffered values\n");
    return true;
}

// 清除g_bbn_pub中的所有数据
void bbn_reset_buffer(void) {
    memset(&g_bbn_pub, 0, sizeof(bbn_pub_t));
}