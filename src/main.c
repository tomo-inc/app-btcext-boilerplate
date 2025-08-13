#include <stdbool.h>
#include <inttypes.h>
#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/common/psbt.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map_value.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkle_leaf_element.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/handler/sign_psbt/txhashes.h"
#include "../bitcoin_app_base/src/crypto.h"
#include "bbn_def.h"
#include "bbn_pub.h"
#include "bbn_tlv.h"
#include "bbn_data.h"
#include "bbn_script.h"
#include "bbn_script.h"
#include "bbn_address.h"
#include "display.h"


bool custom_apdu_handler(dispatcher_context_t *dc, const command_t *cmd) {
    uint64_t data_length;
    uint8_t data_merkle_root[32];
    PRINTF("Custom APDU handler called with CLA: 0x%02x, INS: 0x%02x\n", cmd->cla, cmd->ins);

    if (cmd->cla != CLA_APP) {
        return false;
    }

    if (cmd->ins == INS_CUSTOM_TLV) {
        PRINTF("Handling custom APDU INS_CUSTOM_TLV\n");
        PRINTF("&dc->read_buffer %x\n", &dc->read_buffer);
        PRINTF_BUF(&dc->read_buffer, dc->read_buffer.size);

        if (!buffer_read_varint(&dc->read_buffer, &data_length) ||
            !buffer_read_bytes(&dc->read_buffer, data_merkle_root, 32)) {
            SEND_SW(dc, SW_WRONG_DATA_LENGTH);
            return false;
        }

        PRINTF("Data length: %d\n", (int) data_length);
        PRINTF("Merkle root: ");
        PRINTF_BUF(data_merkle_root, 32);

        size_t n_chunks = (data_length + CHUNK_SIZE - 1) / CHUNK_SIZE;

        uint8_t complete_data[1024];

        size_t received_data = 0;
        for (unsigned int i = 0; i < n_chunks; i++) {
            uint8_t chunk[CHUNK_SIZE];
            int chunk_len =
                call_get_merkle_leaf_element(dc, data_merkle_root, n_chunks, i, chunk, CHUNK_SIZE);
            PRINTF("chunk_len:%d %d\n", i, chunk_len);

            if (chunk_len < 0 || (chunk_len != CHUNK_SIZE && i != n_chunks - 1)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            size_t copy_len = (received_data + chunk_len <= data_length)
                                  ? chunk_len
                                  : (data_length - received_data);
            memcpy(complete_data + received_data, chunk, copy_len);
            received_data += copy_len;
        }

        PRINTF("All %d bytes received, parsing TLV data...\n", (int) received_data);
        PRINTF_BUF(complete_data, received_data);

        if (!parse_tlv_data(complete_data, received_data)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        cx_sha256_t hash_ctx;
        cx_sha256_init(&hash_ctx);
        crypto_hash_update(&hash_ctx.header, complete_data, received_data);

        uint8_t final_hash[32];
        crypto_hash_digest(&hash_ctx.header, final_hash, 32);
        PRINTF("final_hash: ");
        PRINTF_BUF(final_hash, 32);

        dc->add_to_response(final_hash, 32);
        SEND_SW(dc, SW_OK);
        return true;
    }

    return false;
}

static bool validate_transaction(dispatcher_context_t *dc,
                                 sign_psbt_state_t *st,
                                 const uint8_t internal_inputs[64],
                                 const uint8_t internal_outputs[64]) {
    PRINTF("Validating transaction\n");
    return true;
}

/**
 * @brief Validates and displays the transaction's Clear Signing UX for user confirmation.
 *
 * This function is called during the signing process, and is responsible for validating
 * the transaction, and showing the appropriate Clear Signing UX.
 *
 * Inputs are considered internal if they belong to the wallet policy, and outputs are internal
 * if they are valid change outputs.
 *
 * It is the responsibility of this function to validate all the remaining inputs and outputs.
 * This function MUST fail if any unexpected inputs/outputs are found.
 *
 * This function must return false if the signing flow should not continue. In that case, an
 * error status word should be sent. If the function returns true, no status word should be sent,
 * and the signing flow will continue.
 *
 * @param dc Dispatcher context.
 * @param st PSBT signing state.
 * @param internal_inputs Bitvector representing internal inputs.
 * @param internal_outputs Bitvector representing internal outputs.
 * @return true if validated and displayed successfully, false otherwise.
 */
bool validate_and_display_transaction(dispatcher_context_t *dc,
                                      sign_psbt_state_t *st,
                                      const uint8_t internal_inputs[64],
                                      const uint8_t internal_outputs[64]) {
    PRINTF("Validating and displaying transaction\n");
    if(!bbn_get_final_path(g_bbn_data.derive_path, &g_bbn_data.derive_path_len)){
        return false;
    }
    // get staker public key
    // use path from psbt
    uint8_t pubkey[32];
    if(!bbn_derive_pubkey(g_bbn_data.derive_path,g_bbn_data.derive_path_len, BIP32_PUBKEY_VERSION,
                      pubkey)) {
        PRINTF("Failed to derive pubkey\n");
        return false;
    }
    PRINTF("g_bbn_data.staker_pk: ");
    PRINTF_BUF(g_bbn_data.staker_pk, 32);
    // TODO:
    // need to compare the staker pk in taproot script if have
    memcpy(g_bbn_data.staker_pk, pubkey, 32);
    g_bbn_data.has_staker_pk = true;

    if (!validate_transaction(dc, st, internal_inputs, internal_outputs)) {
        return false;
    }

    display_actions(dc, g_bbn_data.action_type);
    PRINTF("action_type: %d\n", g_bbn_data.action_type);

    if (g_bbn_data.has_fp_list) {
        if (!display_public_keys(dc, g_bbn_data.fp_count, g_bbn_data.fp_list, BBN_DIS_PUB_FP, 0)) {
            PRINTF("display_public_keys failed\n");
            return false;
        }
    }

    if (g_bbn_data.has_cov_key_list) {
        if (!display_public_keys(dc,
                                 g_bbn_data.cov_key_count,
                                 g_bbn_data.cov_key_list,
                                 BBN_DIS_PUB_COV,
                                 g_bbn_data.cov_quorum)) {
            PRINTF("display_public_keys failed\n");
            return false;
        }
    }
    if (g_bbn_data.has_timelock) {
        if (!display_timelock(dc, (uint32_t) g_bbn_data.timelock)) {
            PRINTF("display_timelock failed\n");
            return false;
        }
    }

    if (!display_external_outputs(dc, st, internal_outputs)) {
        PRINTF("display_external_outputs fail \n");
        return false;
    }
    if (st->warnings.high_fee && !ui_warn_high_fee(dc)) {
        PRINTF("ui_warn_high_fee fail \n");
        SEND_SW(dc, SW_DENY);
        return false;
    }

    switch (g_bbn_data.action_type) {
        case BBN_POLICY_SLASHING:
        case BBN_POLICY_SLASHING_UNBONDING:
            PRINTF("bbn_check_slashing_address\n");
            if (!bbn_check_slashing_address(st, g_bbn_data.staker_pk)) {
                PRINTF("bbn_check_slashing_address failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            break;
        case BBN_POLICY_STAKE_TRANSFER:
            PRINTF("bbn_check_staking_address\n");
            if (!bbn_check_staking_address(st)) {
                PRINTF("bbn_check_staking_address failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            break;
        case BBN_POLICY_UNBOND:
            PRINTF("bbn_check_unbond_address\n");
            if (!bbn_check_unbond_address(st)) {
                PRINTF("bbn_check_unbond_address failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            break;
        default:
            return false;
    }

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    PRINTF("st->inputs_total_amount=%d,st->outputs.total_amount=%d\n",
           (uint32_t) st->inputs_total_amount,
           (uint32_t) st->outputs.total_amount);
    PRINTF("Fee: %d\n", (uint32_t) fee);
    if (!ui_validate_transaction(dc, COIN_COINID_SHORT, fee, false)) {
        PRINTF("ui_validate_transaction fail \n");
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

/**
 * @brief Signs the custom (special) input.
 *
 * This function must be implemented in order to sign for all the inputs that are not internal.
 * If not implemented, only the internal inputs are signed (handled by the base app).
 *
 * This function must return false in case of any error. In that case, an error status word should
 * be sent. If the function returns true, no status word should be sent.
 *
 * @param dc Dispatcher context.
 * @param st PSBT signing state.
 * @param tx_hashes Transaction hashes.
 * @param internal_inputs Bitvector representing internal inputs.
 * @return true if signing was successful, false otherwise.
 */
bool sign_custom_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    tx_hashes_t *tx_hashes,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    PRINTF("Signing custom inputs\n");
    PRINTF("st->n_inputs: %d\n", st->n_inputs);
    // 遍历所有输入，找到外部输入并签名
    for (unsigned int i = 0; i < st->n_inputs; i++) {
        if (bitvector_get(internal_inputs, i) == 0) {  // 外部输入
            PRINTF("Signing external input %d\n", i);
            // 获取当前输入的map
            merkleized_map_commitment_t input_map;
            if (0 > call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &input_map)) {
                PRINTF("Failed to get input map for input %d\n", i);
                return false;
            }
            uint8_t sighash[32];
            uint8_t leafhash[32];
            uint8_t *pLeaf;
            switch (g_bbn_data.action_type) {
                case BBN_POLICY_SLASHING:
                case BBN_POLICY_SLASHING_UNBONDING:
                    compute_bbn_leafhash_slashing(leafhash);
                    pLeaf = leafhash;
                    PRINTF("leafhash BBN_POLICY_SLASHING BBN_POLICY_SLASHING_UNBONDING\n");
                    break;
                case BBN_POLICY_STAKE_TRANSFER:
                    pLeaf = NULL;
                    PRINTF("leafhash BBN_POLICY_STAKE_TRANSFER\n");
                    break;
                case BBN_POLICY_UNBOND:
                    compute_bbn_leafhash_unbonding(leafhash);
                    pLeaf = leafhash;
                    PRINTF("leafhash BBN_POLICY_UNBOND\n");
                    break;
                default:
                    break;
            }
            if (!compute_sighash_segwitv1(dc, st, tx_hashes, 
                                          &input_map,  // 当前输入的map
                                          i,           // 当前输入的索引
                                          g_bbn_data.g_input_scriptPubKey,
                                          sizeof(g_bbn_data.g_input_scriptPubKey),
                                          pLeaf,
                                          SIGHASH_DEFAULT,
                                          sighash)) {
                PRINTF("Failed to compute sighash for input %d\n", i);
                return false;
            }
            if (!sign_sighash_schnorr_and_yield(dc, st, i, g_bbn_data.derive_path, g_bbn_data.derive_path_len,
                                                NULL, 0, leafhash, SIGHASH_DEFAULT, sighash)) {
                PRINTF("Failed to sign input %d\n", i);
                return false;
            }
            
            PRINTF("Signed external input %d\n", i);
        }
    }
    
    return true;
}