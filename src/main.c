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
#include "bbn_schnorr.h"
#include "display.h"

bool psbt_get_txid_signmessage(dispatcher_context_t *dc, sign_psbt_state_t *st, uint8_t *txid) {
    merkleized_map_commitment_t ith_map;
    int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, 0, &ith_map);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // get prevout hash and output index for the i-th input
    uint8_t ith_prevout_hash[32];
    if (32 != call_get_merkleized_map_value(dc,
                                            &ith_map,
                                            (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                            1,
                                            ith_prevout_hash,
                                            32)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    memcpy(txid, ith_prevout_hash, 32);  // to save memory
    return true;
}
bool psbt_get_tapleaf_script(dispatcher_context_t *dc,
                             const merkleized_map_commitment_t *input_map,
                             uint8_t *leaf_script,
                             int32_t leaf_script_len) {
    uint8_t buf[256];
    int32_t len = call_get_merkleized_map_value(dc,
                                                input_map,
                                                (uint8_t[]){PSBT_IN_TAP_LEAF_SCRIPT},
                                                1,
                                                buf,
                                                sizeof(buf));
    if (len < 0 || len > leaf_script_len) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    memcpy(leaf_script, buf, len);

    return true;
}

bool custom_apdu_handler(dispatcher_context_t *dc, const command_t *cmd) {
    uint64_t data_length;
    uint8_t data_merkle_root[32];
    if (cmd->cla != CLA_APP) {
        return false;
    }
    /* Disabling SIGN_MESSAGE command */
    if (cmd->ins == SIGN_MESSAGE) {
        io_send_sw(SW_CLA_NOT_SUPPORTED);
        return true;
    }

    if (cmd->ins == INS_CUSTOM_TLV) {
        if (!buffer_read_varint(&dc->read_buffer, &data_length) ||
            !buffer_read_bytes(&dc->read_buffer, data_merkle_root, 32)) {
            SEND_SW(dc, SW_WRONG_DATA_LENGTH);
            return false;
        }
        size_t n_chunks = (data_length + CHUNK_SIZE - 1) / CHUNK_SIZE;

        if (n_chunks > MAX_CHUNK_COUNT) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t complete_data[1024];

        size_t received_data = 0;
        for (unsigned int i = 0; i < n_chunks; i++) {
            uint8_t chunk[CHUNK_SIZE];
            int chunk_len =
                call_get_merkle_leaf_element(dc, data_merkle_root, n_chunks, i, chunk, CHUNK_SIZE);

            if (chunk_len < 0 || (chunk_len != CHUNK_SIZE && i != n_chunks - 1)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            size_t copy_len = (received_data + chunk_len <= data_length)
                                  ? chunk_len
                                  : (data_length - received_data);
            if (copy_len + received_data > sizeof(complete_data)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            memcpy(complete_data + received_data, chunk, copy_len);
            received_data += copy_len;
        }

        if (!parse_tlv_data(complete_data, received_data)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        PRINTF("TLV data parsed successfully\n");
        PRINTF("g_bbn_data.action_type: %d\n", g_bbn_data.action_type);
        // buffer pubkeys when slashing
        if (g_bbn_data.action_type == BBN_POLICY_SLASHING) {
            bbn_buffer_pubkeys();
        }

        cx_sha256_t hash_ctx;
        cx_sha256_init(&hash_ctx);
        crypto_hash_update(&hash_ctx.header, complete_data, received_data);

        uint8_t final_hash[32];
        crypto_hash_digest(&hash_ctx.header, final_hash, 32);
        dc->add_to_response(final_hash, 32);
        SEND_SW(dc, SW_OK);
        return true;
    }

    return false;
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
    UNUSED(internal_inputs);

    PRINTF("g_bbn_data.derive_path_len: %d\n", g_bbn_data.derive_path_len);
    PRINTF("g_bbn_data.derive_path: ");
    for (size_t i = 0; i < g_bbn_data.derive_path_len; i++) {
        PRINTF("0x%x ", g_bbn_data.derive_path[i]);
    }
    PRINTF("\n");

    // get staker public key
    // use path from psbt
    uint8_t pubkey[32];
    if (!bbn_derive_pubkey(g_bbn_data.derive_path, g_bbn_data.derive_path_len, pubkey)) {
        bbn_reset_buffer();
        PRINTF("Failed to derive pubkey\n");
        return false;
    }
    // TODO:
    // need to compare the staker pk in taproot script if have
    memcpy(g_bbn_data.staker_pk, pubkey, 32);
    g_bbn_data.has_staker_pk = true;
    PRINTF("g_bbn_data.staker_pk: ");
    PRINTF_BUF(g_bbn_data.staker_pk, 32);
    PRINTF("action_type: %d\n", g_bbn_data.action_type);

    // 集中判断是否需要显示公钥
    bool show_fp_keys = false;
    bool show_cov_keys = false;

    switch (g_bbn_data.action_type) {
        case BBN_POLICY_SLASHING:
        case BBN_POLICY_UNBOND:
        case BBN_POLICY_EXPANSION:
            // 这些 action 无条件显示公钥
            show_fp_keys = true;
            show_cov_keys = true;
            break;
        case BBN_POLICY_SLASHING_UNBONDING:
        case BBN_POLICY_STAKE_TRANSFER:
            // 这些 action 仅当公钥与缓存不一致时才显示
            if (!bbn_compare_pubkeys()) {
                show_fp_keys = true;
                show_cov_keys = true;
            }
            break;
        case BBN_POLICY_BIP322:
        case BBN_POLICY_WITHDRAW:
        default:
            // 不显示公钥
            break;
    }

    // 统一处理 fp_keys 显示
    if (show_fp_keys) {
        if (!g_bbn_data.has_fp_list) {
            bbn_reset_buffer();
            PRINTF("No finality provider public keys\n");
            return false;
        }
        if (!display_public_keys(dc, g_bbn_data.fp_count, g_bbn_data.fp_list, BBN_DIS_PUB_FP, 0)) {
            bbn_reset_buffer();
            PRINTF("display_public_keys failed\n");
            return false;
        }
    }

    // 统一处理 cov_keys 显示
    if (show_cov_keys) {
        if (!g_bbn_data.has_cov_key_list) {
            bbn_reset_buffer();
            PRINTF("No covenant public keys\n");
            return false;
        }
        if (!display_cov_public_keys(dc,
                                     g_bbn_data.cov_key_count,
                                     g_bbn_data.cov_key_list,
                                     g_bbn_data.cov_quorum)) {
            bbn_reset_buffer();
            PRINTF("display_cov_public_keys failed\n");
            return false;
        }
    }

    // 显示 action 确认
    if (g_bbn_data.action_type == BBN_POLICY_BIP322) {
        if (!ui_confirm_bbn_message(dc)) {
            bbn_reset_buffer();
            PRINTF("ui_confirm_bbn_message failed\n");
            SEND_SW(dc, SW_DENY);
            return false;
        }
    } else {
        if (!display_actions(dc, g_bbn_data.action_type)) {
            bbn_reset_buffer();
            PRINTF("display_actions failed\n");
            SEND_SW(dc, SW_DENY);
            return false;
        }
    }

    if (g_bbn_data.has_timelock) {
        if (g_bbn_data.action_type != BBN_POLICY_SLASHING &&
            g_bbn_data.action_type != BBN_POLICY_SLASHING_UNBONDING) {
            if (!display_timelock(dc, (uint32_t) g_bbn_data.timelock)) {
                bbn_reset_buffer();
                PRINTF("display_timelock failed\n");
                return false;
            }
        }
    }

    if (!display_external_outputs(dc, st, internal_outputs)) {
        bbn_reset_buffer();
        PRINTF("display_external_outputs fail \n");
        return false;
    }

    if (st->warnings.high_fee && !ui_warn_high_fee(dc)) {
        bbn_reset_buffer();
        PRINTF("ui_warn_high_fee fail \n");
        SEND_SW(dc, SW_DENY);
        return false;
    }
    uint8_t psbt_txid[32];
    switch (g_bbn_data.action_type) {
        case BBN_POLICY_SLASHING:
        case BBN_POLICY_SLASHING_UNBONDING:
            if (!bbn_check_slashing_address(st)) {
                PRINTF("bbn_check_slashing_address failed\n");
                bbn_reset_buffer();
                SEND_SW(dc, SW_DENY);
                return false;
            }
            break;
        case BBN_POLICY_STAKE_TRANSFER:
            if (!bbn_check_staking_address(st)) {
                bbn_reset_buffer();
                PRINTF("bbn_check_staking_address failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            bbn_reset_buffer();
            break;
        case BBN_POLICY_UNBOND:
            if (!bbn_check_unbond_address(st)) {
                bbn_reset_buffer();
                PRINTF("bbn_check_unbond_address failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            break;
        case BBN_POLICY_BIP322:
            if (!psbt_get_txid_signmessage(dc, st, psbt_txid)) {
                bbn_reset_buffer();
                PRINTF("psbt_get_txid_signmessage failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            if (!bbn_check_message(psbt_txid)) {
                bbn_reset_buffer();
                PRINTF("bbn_check_message_key failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            break;
        case BBN_POLICY_WITHDRAW:
            break;
        case BBN_POLICY_EXPANSION:
            if (!bbn_check_staking_address(st)) {
                bbn_reset_buffer();
                PRINTF("bbn_check_expansion_address failed\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
            break;
        default:
            return false;
    }

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    if (!ui_validate_transaction(dc, COIN_COINID_SHORT, fee, false)) {
        bbn_reset_buffer();
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
    // Check input counts based on action type
    switch (g_bbn_data.action_type) {
        case BBN_POLICY_SLASHING:
        case BBN_POLICY_SLASHING_UNBONDING:
        case BBN_POLICY_UNBOND:
        case BBN_POLICY_BIP322:
            // These actions must have exactly 1 input
            if (st->n_inputs != 1) {
                PRINTF("Invalid input count for action %d: expected 1, got %d\n",
                       g_bbn_data.action_type,
                       st->n_inputs);
                bbn_reset_buffer();
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            break;

        case BBN_POLICY_EXPANSION:
            // Expansion must have exactly 2 inputs
            // input[0]: original staking output (stake-output)
            // input[1]: UTXO to pay fee or increase staking amount
            if (st->n_inputs != 2) {
                bbn_reset_buffer();
                PRINTF("Invalid input count for expansion: expected 2, got %d\n", st->n_inputs);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            PRINTF("Expansion transaction with 2 inputs:\n");
            PRINTF("  Input[0]: Staking output (script path unlock)\n");
            PRINTF("  Input[1]: Fee/Amount UTXO\n");
            break;

        case BBN_POLICY_STAKE_TRANSFER:
            // Stake transfer can have multiple inputs (>= 1)
            if (st->n_inputs < 1) {
                bbn_reset_buffer();
                PRINTF("Invalid input count for stake transfer: expected >= 1, got %d\n",
                       st->n_inputs);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            PRINTF("Stake transfer with %d input(s)\n", st->n_inputs);
            break;

        case BBN_POLICY_WITHDRAW:
            // Withdraw must have exactly 1 input
            if (st->n_inputs != 1) {
                bbn_reset_buffer();
                PRINTF("Invalid input count for withdraw: expected 1, got %d\n", st->n_inputs);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            break;

        default:
            bbn_reset_buffer();
            PRINTF("Unknown action type: %d\n", g_bbn_data.action_type);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
    }

    for (unsigned int i = 0; i < st->n_inputs; i++) {
        if (bitvector_get(internal_inputs, i) == 0) {  // 外部输入
            PRINTF("Signing external input %d\n", i);
            // 获取当前输入的map
            merkleized_map_commitment_t input_map;
            if (0 > call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &input_map)) {
                bbn_reset_buffer();
                PRINTF("Failed to get input map for input %d\n", i);
                return false;
            }
            int segwit_version = get_policy_segwit_version(st->wallet_policy_map);

            uint8_t sighash[32];
            uint8_t leafhash[32];
            uint8_t *pLeaf = NULL;
            switch (g_bbn_data.action_type) {
                case BBN_POLICY_SLASHING:
                case BBN_POLICY_SLASHING_UNBONDING:
                    compute_bbn_leafhash_slashing(leafhash);
                    pLeaf = leafhash;
                    segwit_version = 1;  // force taproot
                    break;
                case BBN_POLICY_STAKE_TRANSFER:
                    pLeaf = NULL;
                    break;
                case BBN_POLICY_UNBOND:
                    compute_bbn_leafhash_unbonding(leafhash);
                    pLeaf = leafhash;
                    segwit_version = 1;  // force taproot
                    break;
                case BBN_POLICY_WITHDRAW:
                    compute_bbn_leafhash_timelock(leafhash);
                    pLeaf = leafhash;
                    segwit_version = 1;  // force taproot
                    break;
                case BBN_POLICY_EXPANSION:
                    if (i == 0) {
                        // Input[0]: staking output, needs script path (unbonding script)
                        compute_bbn_leafhash_unbonding(leafhash);
                        pLeaf = leafhash;
                        segwit_version = 1;  // force taproot
                        PRINTF("Input[0]: Using script path with unbonding leaf\n");
                    } else if (i == 1) {
                        // Input[1]: normal UTXO, use key path (no script)
                        pLeaf = NULL;
                    } else {
                        bbn_reset_buffer();
                        // not possible
                        PRINTF("more then two input for expansion\n");
                        return false;
                    }
                    break;
                default:
                    break;
            }

            if (segwit_version == 0)  // native segwit
            {
                PRINTF("native segwit %d\n", segwit_version);
                uint8_t witness_utxo_buf[8 + 1 + 34];  // 8字节金额 + 1字节脚本长度 + 最多34字节脚本
                int witness_utxo_len =
                    call_get_merkleized_map_value(dc,
                                                  &input_map,
                                                  (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                                  1,
                                                  witness_utxo_buf,
                                                  sizeof(witness_utxo_buf));

                if (witness_utxo_len < 10) {
                    bbn_reset_buffer();
                    PRINTF("Failed to get witness_utxo\n");
                    return false;
                }

                // 解析 scriptPubKey
                uint8_t script_len = witness_utxo_buf[8];       // 第9字节是脚本长度
                uint8_t *script_pubkey = witness_utxo_buf + 9;  // 紧跟在长度后面
                PRINTF("scriptPubKey len: %d\n", script_len);
                PRINTF_BUF(script_pubkey, script_len);

                // segwitv0 inputs default to SIGHASH_ALL
                if (!compute_sighash_segwitv0(dc,
                                              st,
                                              tx_hashes,
                                              &input_map,
                                              i,
                                              script_pubkey,
                                              script_len,
                                              SIGHASH_ALL,
                                              sighash))
                    return false;
                PRINTF("sighash: ");
                PRINTF_BUF(sighash, 32);

                if (!sign_sighash_ecdsa_and_yield(dc,
                                                  st,
                                                  i,
                                                  g_bbn_data.derive_path,
                                                  g_bbn_data.derive_path_len,
                                                  SIGHASH_ALL,
                                                  sighash)) {
                    bbn_reset_buffer();
                    return false;
                }

            } else if (segwit_version == 1) {  // taproot
                if (!compute_sighash_segwitv1(dc,
                                              st,
                                              tx_hashes,
                                              &input_map,  // 当前输入的map
                                              i,           // 当前输入的索引
                                              g_bbn_data.g_input_scriptPubKey,
                                              sizeof(g_bbn_data.g_input_scriptPubKey),
                                              pLeaf,
                                              SIGHASH_DEFAULT,
                                              sighash)) {
                    bbn_reset_buffer();
                    PRINTF("Failed to compute sighash for input %d\n", i);
                    return false;
                }
                PRINTF("sighash: ");
                PRINTF_BUF(sighash, 32);
                uint8_t dummy[128];
                const uint8_t *tweak_data = dummy;
                size_t tweak_data_len = 0;
                if (g_bbn_data.action_type != BBN_POLICY_STAKE_TRANSFER &&
                    g_bbn_data.action_type != BBN_POLICY_EXPANSION) {
                    tweak_data = NULL;
                    tweak_data_len = 0;
                }
                if (g_bbn_data.action_type == BBN_POLICY_EXPANSION) {
                    if (i == 0) {
                        tweak_data = NULL;
                        tweak_data_len = 0;
                    }
                }

                if (!bbn_sign_sighash_schnorr_and_yield(dc,
                                                        st,
                                                        i,
                                                        g_bbn_data.derive_path,
                                                        g_bbn_data.derive_path_len,
                                                        tweak_data,
                                                        tweak_data_len,
                                                        pLeaf,
                                                        SIGHASH_DEFAULT,
                                                        sighash)) {
                    bbn_reset_buffer();
                    PRINTF("Failed to sign input %d\n", i);
                    return false;
                }
            } else {
                // should never happen in babtlon
            }
        }
    }

    PRINTF("Signed external input\n");
    return true;
}