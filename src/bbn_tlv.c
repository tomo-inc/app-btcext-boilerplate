#include <stdbool.h>
#include <stdint.h>
#include <string.h>
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

    bbn_data_reset();

    PRINTF("=== TLV Data Parsing ===\n");

    while (offset < data_len) {
        if (offset + 1 >= data_len) {
            PRINTF("Error: Not enough data for TAG\n");
            return false;
        }

        uint8_t tag = data[offset++];
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
                if (length >= 1 && value != NULL) {
                    uint8_t action = value[0];
                    g_bbn_data.has_action_type = true;
                    g_bbn_data.action_type = action;
                } else {
                    PRINTF("  -> Invalid Action Type length or NULL value\n");
                    return false;
                }
                break;
            case TAG_FP_COUNT:
                if (length == 1) {
                    g_bbn_data.has_fp_count = true;
                    g_bbn_data.fp_count = value[0];
                } else {
                    PRINTF("  -> Invalid FP Count length\n");
                    return false;
                }
                break;
            case TAG_FP_LIST:
                PRINTF("  -> Finality Provider List (%d pubkeys):\n", length / 32);
                if (length / 32 <= MAX_FP_COUNT) {
                    g_bbn_data.has_fp_list = true;
                    for (int j = 0; j < length / 32; j++) {
                        memcpy(g_bbn_data.fp_list[j], value + j * 32, 32);
                    }
                } else {
                    PRINTF("  -> Too many FP keys (max %d)\n", MAX_FP_COUNT);
                    return false;
                }
                break;

            case TAG_COV_KEY_COUNT:
                if (length == 1) {
                    g_bbn_data.has_cov_key_count = true;
                    g_bbn_data.cov_key_count = value[0];
                } else {
                    return false;
                }
                break;

            case TAG_COV_KEY_LIST:
                if (length / 32 <= MAX_COV_KEY_COUNT) {
                    g_bbn_data.has_cov_key_list = true;
                    for (int j = 0; j < length / 32; j++) {
                        memcpy(g_bbn_data.cov_key_list[j], value + j * 32, 32);
                    }
                } else {
                    PRINTF("  -> Too many COV keys (max %d)\n", MAX_COV_KEY_COUNT);
                    return false;
                }
                break;
            case TAG_STAKER_PK:
                if (length == 32) {
                    g_bbn_data.has_staker_pk = true;
                    memcpy(g_bbn_data.staker_pk, value, 32);
                } else {
                    PRINTF("  -> Invalid Staker PK length\n");
                    return false;
                }
                break;
            case TAG_COV_QUORUM:
                if (length == 1) {
                    g_bbn_data.has_cov_quorum = true;
                    g_bbn_data.cov_quorum = value[0];
                } else {
                    PRINTF("  -> Invalid Cov Quorum length\n");
                    return false;
                }
                break;
            case TAG_FP_QUORUM:
                if (length == 1) {
                    g_bbn_data.has_fp_quorum = true;
                    g_bbn_data.fp_quorum = value[0];
                } else {
                    PRINTF("  -> Invalid FP Quorum length\n");
                    return false;
                }
                break;
            case TAG_TIMELOCK:
                if (length == 8) {
                    uint64_t timelock = read_u64_be(value, 0);
                    g_bbn_data.has_timelock = true;
                    g_bbn_data.timelock = timelock;
                } else {
                    PRINTF("  -> Invalid Timelock length\n");
                    return false;
                }
                break;

            case TAG_SLASHING_FEE_LIMIT:
                if (length == 8) {
                    uint64_t limit = read_u64_be(value, 0);
                    g_bbn_data.has_slashing_fee_limit = true;
                    g_bbn_data.slashing_fee_limit = limit;
                } else {
                    PRINTF("  -> Invalid Slashing Fee Limit length\n");
                    return false;
                }
                break;
            case TAG_UNBONDING_FEE_LIMIT:
                if (length == 8) {
                    uint64_t limit = read_u64_be(value, 0);
                    g_bbn_data.has_unbonding_fee_limit = true;
                    g_bbn_data.unbonding_fee_limit = limit;
                } else {
                    PRINTF("  -> Invalid Unbonding Fee Limit length\n");
                    return false;
                }
                break;
            case TAG_MESSAGE:
                if (length <= sizeof(g_bbn_data.message)) {
                    memcpy(g_bbn_data.message, value, length);
                    g_bbn_data.has_message = true;
                    g_bbn_data.message_len = length;
                } else {
                    PRINTF("  -> Message length exceeds maximum size\n");
                    return false;
                }
                break;
            case TAG_TXID:
                if (length == 32) {
                    memcpy(g_bbn_data.txid, value, 32);
                    g_bbn_data.has_txid = true;
                } else {
                    PRINTF("  -> Invalid Transaction ID length\n");
                    return false;
                }
                break;
            case TAG_BURN_ADDRESS:
                if (length >= 1 && length <= 32) {
                    memcpy(g_bbn_data.burn_address, value, length);
                    g_bbn_data.has_burn_address = true;
                    g_bbn_data.burn_address_len = length;
                } else {
                    PRINTF("  -> Invalid Burning Address length\n");
                    return false;
                }
                break;
            case TAG_MESSAGE_KEY:
                if (length == 32) {
                    memcpy(g_bbn_data.message_key, value, 32);
                    g_bbn_data.has_message_key = true;
                } else {
                    PRINTF("  -> Invalid Message Key length\n");
                    return false;
                }
                break;
            case TAG_BIP32_PATH:
                if (length <= sizeof(g_bbn_data.derive_path) && length % 4 == 0) {
                    for (uint32_t i = 0; i < length / 4; i++) {
                        g_bbn_data.derive_path[i] = read_u32_be(value, i * 4);
                    }
                    g_bbn_data.derive_path_len = length / 4;
                } else {
                    PRINTF("  -> Invalid BIP32 Path length\n");
                    return false;
                }
                break;
            default:
                PRINTF("  -> Unknown TAG: 0x%02x\n", tag);
                return false;
        }

        offset += length;
    }
    return true;
}

void bbn_data_reset(void) {
    memset(&g_bbn_data, 0, sizeof(bbn_data_t));
}