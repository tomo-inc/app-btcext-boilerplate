#include <stdbool.h>
#include <stdint.h>
#include "../bitcoin_app_base/src/common/psbt.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/common/read.h"
#include "bbn_def.h"
#include "bbn_data.h"
#include "bbn_tlv.h"
#include "display.h"

bool parse_tlv_data(const uint8_t *data, uint32_t data_len) {
    uint32_t offset = 0;

    // 重置全局数据结构体
    bbn_data_reset();

    PRINTF("=== TLV Data Parsing ===\n");

    while (offset < data_len) {
        if (offset + 1 >= data_len) {
            PRINTF("Error: Not enough data for TAG\n");
            return false;
        }

        uint8_t tag = data[offset++];

        // 读取长度（假设长度字段为2字节）
        uint16_t length = 0;
        if (offset >= data_len) {
            PRINTF("Error: Not enough data for LENGTH\n");
            return false;
        }

        if (offset + 2 > data_len) {
            PRINTF("Error: Not enough data for 2-byte LENGTH\n");
            return false;
        }
        length = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        if (offset + length > data_len) {
            PRINTF("Error: Not enough data for VALUE (need %d bytes, have %d)\n",
                   length,
                   (int) (data_len - offset));
            return false;
        }

        const uint8_t *value = &data[offset];

        PRINTF("TAG: 0x%02x, LEN: %d, VALUE: ", tag, length);
        PRINTF_BUF(value, length);

        // 根据TAG类型解析具体内容并存储到全局结构体
        switch (tag) {
            case TAG_ACTION_TYPE:
                PRINTF("  -> Action Type\n");
                if (length >= 1 && value != NULL) {
                    uint8_t action = value[0];

                    // 存储到全局变量
                    g_bbn_data.has_action_type = true;
                    g_bbn_data.action_type = action;
                } else {
                    PRINTF("  -> Invalid Action Type length or NULL value\n");
                }
                break;

            case TAG_FP_COUNT:
                if (length == 1) {
                    PRINTF("  -> Finality Provider Count: %d\n", value[0]);

                    // 存储到全局变量
                    g_bbn_data.has_fp_count = true;
                    g_bbn_data.fp_count = value[0];
                } else {
                    PRINTF("  -> Invalid FP Count length\n");
                }
                break;

            case TAG_FP_LIST:
                PRINTF("  -> Finality Provider List (%d pubkeys):\n", length / 32);
                if (length / 32 <= MAX_FP_COUNT) {
                    g_bbn_data.has_fp_list = true;
                    for (int j = 0; j < length / 32; j++) {
                        PRINTF("    FP[%d]: ", j);
                        PRINTF_BUF(value + j * 32, 32);

                        // 存储到全局变量
                        memcpy(g_bbn_data.fp_list[j], value + j * 32, 32);
                    }
                } else {
                    PRINTF("  -> Too many FP keys (max %d)\n", MAX_FP_COUNT);
                }
                break;

            case TAG_COV_KEY_COUNT:
                if (length == 1) {
                    PRINTF("  -> Covenant Key Count: %d\n", value[0]);

                    // 存储到全局变量
                    g_bbn_data.has_cov_key_count = true;
                    g_bbn_data.cov_key_count = value[0];
                } else {
                    PRINTF("  -> Invalid Cov Key Count length\n");
                }
                break;

            case TAG_COV_KEY_LIST:
                PRINTF("  -> Covenant Key List (%d pubkeys):\n", length / 32);
                if (length / 32 <= MAX_COV_KEY_COUNT) {
                    g_bbn_data.has_cov_key_list = true;
                    for (int j = 0; j < length / 32; j++) {
                        PRINTF("    COV[%d]: ", j);
                        PRINTF_BUF(value + j * 32, 32);

                        // 存储到全局变量
                        memcpy(g_bbn_data.cov_key_list[j], value + j * 32, 32);
                    }
                } else {
                    PRINTF("  -> Too many COV keys (max %d)\n", MAX_COV_KEY_COUNT);
                }
                break;

            case TAG_STAKER_PK:
                if (length == 32) {
                    PRINTF("  -> Staker Public Key: ");
                    PRINTF_BUF(value, 32);

                    // 存储到全局变量
                    g_bbn_data.has_staker_pk = true;
                    memcpy(g_bbn_data.staker_pk, value, 32);
                } else {
                    PRINTF("  -> Invalid Staker PK length\n");
                }
                break;

            case TAG_COV_QUORUM:
                if (length == 1) {
                    PRINTF("  -> Covenant Quorum: %d\n", value[0]);

                    // 存储到全局变量
                    g_bbn_data.has_cov_quorum = true;
                    g_bbn_data.cov_quorum = value[0];
                } else {
                    PRINTF("  -> Invalid Cov Quorum length\n");
                }
                break;

            case TAG_TIMELOCK:
                if (length == 8) {
                    uint64_t timelock = read_u64_be(value, 0);
                    PRINTF("  -> Timelock: %d\n", (uint32_t) timelock);

                    // 存储到全局变量
                    g_bbn_data.has_timelock = true;
                    g_bbn_data.timelock = timelock;
                } else {
                    PRINTF("  -> Invalid Timelock length\n");
                }
                break;

            case TAG_SLASHING_FEE_LIMIT:
                if (length == 8) {
                    uint64_t limit = read_u64_be(value, 0);
                    PRINTF("  -> Slashing Fee Limit: %d satoshi\n", (uint32_t) limit);

                    // 存储到全局变量
                    g_bbn_data.has_slashing_fee_limit = true;
                    g_bbn_data.slashing_fee_limit = limit;
                } else {
                    PRINTF("  -> Invalid Slashing Fee Limit length\n");
                }
                break;

            case TAG_UNBONDING_FEE_LIMIT:
                if (length == 8) {
                    uint64_t limit = read_u64_be(value, 0);
                    PRINTF("  -> Unbonding Fee Limit: %d satoshi\n", (uint32_t) limit);

                    // 存储到全局变量
                    g_bbn_data.has_unbonding_fee_limit = true;
                    g_bbn_data.unbonding_fee_limit = limit;
                } else {
                    PRINTF("  -> Invalid Unbonding Fee Limit length\n");
                }
                break;
            case TAG_MESSAGE:
                if (length <= sizeof(g_bbn_data.message)) {
                    PRINTF("  -> Message: ");
                    PRINTF_BUF(value, length);
                    memcpy(g_bbn_data.message, value, length);
                    g_bbn_data.has_message = true;
                    g_bbn_data.message_len = length;
                } else {
                    PRINTF("  -> Message length exceeds maximum size\n");
                }
                break;
            case TAG_TXID:
                if (length == 32) {
                    PRINTF("  -> Transaction ID: ");
                    PRINTF_BUF(value, 32);
                    memcpy(g_bbn_data.txid, value, 32);
                    g_bbn_data.has_txid = true;
                } else {
                    PRINTF("  -> Invalid Transaction ID length\n");
                }
                break;
            case TAG_BURN_ADDRESS:
                if (length >= 1 && length <= 32) {
                    PRINTF("  -> Burning Address (%d bytes): ", length);
                    PRINTF_BUF(value, length);
                    memcpy(g_bbn_data.burn_address, value, length);
                    g_bbn_data.has_burn_address = true;
                    g_bbn_data.burn_address_len = length;
                } else {
                    PRINTF("  -> Invalid Burning Address length\n");
                }
                break;
            default:
                PRINTF("  -> Unknown TAG: 0x%02x\n", tag);
                break;
        }

        offset += length;
    }

    PRINTF("=== TLV Parsing Complete ===\n");
    PRINTF("=== Stored Data Summary ===\n");
    PRINTF("Action Type: %s (value: %d)\n",
           g_bbn_data.has_action_type ? "present" : "missing",
           g_bbn_data.action_type);
    PRINTF("FP Count: %s (value: %d)\n",
           g_bbn_data.has_fp_count ? "present" : "missing",
           g_bbn_data.fp_count);
    PRINTF("COV Count: %s (value: %d)\n",
           g_bbn_data.has_cov_key_count ? "present" : "missing",
           g_bbn_data.cov_key_count);
    PRINTF("Staker PK: %s\n", g_bbn_data.has_staker_pk ? "present" : "missing");
    PRINTF("========================\n");

    return true;
}

void bbn_data_reset(void) {
    memset(&g_bbn_data, 0, sizeof(bbn_data_t));
}