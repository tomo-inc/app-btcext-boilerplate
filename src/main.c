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

#include "bbn_tlv.h"
#include "bbn_data.h"
#include "display.h"

#define H 0x80000000
static const uint32_t magic_pubkey_path[] = {86 ^ H, 1 ^ H, 99 ^ H};

#define P2TR_SCRIPTPUBKEY_LEN 34
// records the value of the special input across calls
static uint64_t magic_input_value;
static int external_input_index;
static merkleized_map_commitment_t external_input_map;
static uint8_t external_input_scriptPubKey[P2TR_SCRIPTPUBKEY_LEN];

#define INS_CUSTOM_XOR 0xbb
#define CHUNK_SIZE 64

bool custom_apdu_handler(dispatcher_context_t *dc, const command_t *cmd) {
    uint64_t data_length;
    uint8_t data_merkle_root[32];
    PRINTF("Custom APDU handler called with CLA: 0x%02x, INS: 0x%02x\n", cmd->cla, cmd->ins);

    if (cmd->cla != CLA_APP) {
        return false;
    }

    if (cmd->ins == INS_CUSTOM_XOR) {
        PRINTF("Handling custom APDU INS_CUSTOM_XOR\n");
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

// validation logic specific to the example 'Foo' protocol
static bool validate_transaction(dispatcher_context_t *dc,
                                 sign_psbt_state_t *st,
                                 const uint8_t internal_inputs[64],
                                 const uint8_t internal_outputs[64]) {
    // check that all inputs are indeed internal, except one
    external_input_index = -1;
    for (unsigned int i = 0; i < st->n_inputs; i++) {
        if (bitvector_get(internal_inputs, i) == 0) {
            if (external_input_index != -1) {
                PRINTF("More than one external input found\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            external_input_index = i;
        }
    }

    if (external_input_index == -1) {
        PRINTF("No external input found\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // check that the external input is rawtr(key) where the key is m/86'/1'/99'

    // obtain the commitment to the i-th output's map
    if (0 > call_get_merkleized_map(dc,
                                    st->inputs_root,
                                    st->n_inputs,
                                    external_input_index,
                                    &external_input_map)) {
        PRINTF("Failed to get input map\n");
        return false;
    }

    // Read the input's witness utxo
    uint8_t witness_utxo[8 + 1 + 34];  // 8 bytes amount; 1 byte length; 34 bytes P2TR Script

    if (8 + 1 + 34 != call_get_merkleized_map_value(dc,
                                                    &external_input_map,
                                                    (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                                    sizeof((uint8_t[]) {PSBT_IN_WITNESS_UTXO}),
                                                    witness_utxo,
                                                    sizeof(witness_utxo))) {
        PRINTF("Failed to get witness utxo, or invalid witness utxo\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
    };
    if (witness_utxo[8] != 34) {
        PRINTF("Unexpected scriptPubKey length in witness utxo: %d\n", witness_utxo[8]);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint8_t *spk = witness_utxo + 9;

    magic_input_value = read_u64_le(witness_utxo, 0);

    serialized_extended_pubkey_t xpub;
    if (0 > get_extended_pubkey_at_path(magic_pubkey_path,
                                        ARRAYLEN(magic_pubkey_path),
                                        BIP32_PUBKEY_VERSION,
                                        &xpub)) {
        PRINTF("Failed getting bip32 pubkey\n");
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    uint8_t *expected_key = xpub.compressed_pubkey + 1;  // x-only key
    external_input_scriptPubKey[0] = 0x51;
    external_input_scriptPubKey[1] = 0x20;
    memcpy(external_input_scriptPubKey + 2, expected_key, 32);
    PRINTF_BUF(external_input_scriptPubKey, 34);
    PRINTF_BUF(spk, 32);
    if (memcmp(spk, external_input_scriptPubKey, P2TR_SCRIPTPUBKEY_LEN) != 0) {
        // the expected special input was not found
        // PRINTF("Invalid scriptPubKey. Where's my magic?\n");

        // SEND_SW(dc, SW_INCORRECT_DATA);
        // return false;
    }

    // check that all outputs are internal (that is, change), except one that is an OP_RETURN with
    // the message "Foo"

    int external_output_index = -1;
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (bitvector_get(internal_outputs, i) == 0) {
            if (external_output_index != -1) {
                // PRINTF("More than one external output found\n");
                // SEND_SW(dc, SW_INCORRECT_DATA);
                // return false;
            }
            external_output_index = i;
        }
    }

    if (external_output_index == -1) {
        PRINTF("No external output found\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // this output is external. Verify that:
    // - it is an OP_RETURN with the "FOO" message
    // - the amount is 0

    // obtain the commitment to the i-th output's map
    merkleized_map_commitment_t output_map;
    if (0 > call_get_merkleized_map(dc,
                                    st->outputs_root,
                                    st->n_outputs,
                                    external_output_index,
                                    &output_map)) {
        PRINTF("Failed to get output map\n");
        return false;
    }

    // Read output amount
    uint8_t raw_amount[8];
    if (8 != call_get_merkleized_map_value(dc,
                                           &output_map,
                                           (uint8_t[]) {PSBT_OUT_AMOUNT},
                                           sizeof((uint8_t[]) {PSBT_OUT_AMOUNT}),
                                           raw_amount,
                                           sizeof(raw_amount))) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t amount = read_u64_le(raw_amount, 0);

    // if (amount != 0) {
    //     PRINTF("External output has non-zero amount\n");
    //     SEND_SW(dc, SW_INCORRECT_DATA);
    //     return false;
    // }

    // Read the output's scriptPubKey
    uint8_t scriptPubKey[32];
    int result_len = call_get_merkleized_map_value(dc,
                                                   &output_map,
                                                   (uint8_t[]) {PSBT_OUT_SCRIPT},
                                                   1,
                                                   scriptPubKey,
                                                   sizeof(scriptPubKey));
    // if (result_len != sizeof(OP_RETURN_FOO) ||
    //     memcmp(scriptPubKey, OP_RETURN_FOO, sizeof(OP_RETURN_FOO)) != 0) {
    //     PRINTF("External output is not an OP_RETURN with the message 'FOO'\n");
    //     SEND_SW(dc, SW_INCORRECT_DATA);
    //     return false;
    // }

    return true;
}
static bool get_output_script_and_amount(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    size_t output_index,
    uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
    size_t *out_scriptPubKey_len,
    uint64_t *out_amount) {
    if (out_scriptPubKey == NULL || out_amount == NULL) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    merkleized_map_commitment_t map;

    // TODO: This might be too slow, as it checks the integrity of the map;
    //       Refactor so that the map key ordering is checked all at the beginning of sign_psbt.
    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, output_index, &map);

    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read output amount
    uint8_t raw_result[8];

    // Read the output's amount
    int result_len = call_get_merkleized_map_value(dc,
                                                   &map,
                                                   (uint8_t[]) {PSBT_OUT_AMOUNT},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
    if (result_len != 8) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t value = read_u64_le(raw_result, 0);
    *out_amount = value;

    // Read the output's scriptPubKey
    result_len = call_get_merkleized_map_value(dc,
                                               &map,
                                               (uint8_t[]) {PSBT_OUT_SCRIPT},
                                               1,
                                               out_scriptPubKey,
                                               MAX_OUTPUT_SCRIPTPUBKEY_LEN);

    if (result_len == -1 || result_len > MAX_OUTPUT_SCRIPTPUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    *out_scriptPubKey_len = result_len;

    return true;
}
static bool __attribute__((noinline)) display_external_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /**
     *  Display all the non-change outputs
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        if (!bitvector_get(internal_outputs, cur_output_index)) {
            // external output, user needs to validate
            uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
            size_t out_scriptPubKey_len;
            uint64_t out_amount;

            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                // we have the output cached, no need to fetch it again
                out_scriptPubKey_len = st->outputs.output_script_lengths[external_outputs_count];
                memcpy(out_scriptPubKey,
                       st->outputs.output_scripts[external_outputs_count],
                       out_scriptPubKey_len);
                out_amount = st->outputs.output_amounts[external_outputs_count];
            } else if (!get_output_script_and_amount(dc,
                                                     st,
                                                     cur_output_index,
                                                     out_scriptPubKey,
                                                     &out_scriptPubKey_len,
                                                     &out_amount)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            ++external_outputs_count;
            PRINTF("out_scriptPubKey (len=%d): ", (int) out_scriptPubKey_len);
            PRINTF_BUF(out_scriptPubKey, out_scriptPubKey_len);
            PRINTF("Output amount: %d satoshi\n", (uint32_t) out_amount);
            // displays the output. It fails if the output is invalid or not supported
            // if (!display_output(dc,
            //                     st,
            //                     cur_output_index,
            //                     external_outputs_count,
            //                     out_scriptPubKey,
            //                     out_scriptPubKey_len,
            //                     out_amount)) {
            //     return false;
            // }
        }
    }

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
    PRINTF("!!!!!!!1*****************  Validating and displaying transaction\n");

    if (!validate_transaction(dc, st, internal_inputs, internal_outputs)) {
        return false;
    }
    uint8_t pubkeys[5][65];
    memset(pubkeys, 0, sizeof(pubkeys));
    memset(pubkeys[0], 0x31, 64);
    memset(pubkeys[1], 0x32, 64);
    memset(pubkeys[2], 0x33, 64);
    memset(pubkeys[3], 0x34, 64);
    memset(pubkeys[4], 0x35, 64);
    if (!display_public_keys(dc, 5, pubkeys, 1)) {
        PRINTF("display_public_keys failed\n");
        return false;
    }

    uint64_t total_input_amount = st->inputs_total_amount;
    uint64_t total_output_amount = st->outputs.total_amount;
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    uint64_t change_amount = st->outputs.change_total_amount;
    uint64_t external_output_amount = total_output_amount - change_amount;

    PRINTF("=== PSBT Transaction Summary ===\n");
    PRINTF("Total Input Amount: %d satoshi\n", (uint32_t) total_input_amount);
    PRINTF("Total Output Amount: %d satoshi\n", (uint32_t) total_output_amount);
    PRINTF("Change Amount: %d satoshi\n", (uint32_t) change_amount);
    PRINTF("External Output Amount: %d satoshi\n", (uint32_t) external_output_amount);
    PRINTF("Transaction Fee: %d satoshi\n", (uint32_t) fee);
    PRINTF("Magic Input Value: %d satoshi\n", (uint32_t) magic_input_value);
    PRINTF("===============================\n");
    int64_t internal_value = st->internal_inputs_total_amount - st->outputs.change_total_amount;
    if (!display_external_outputs(dc, st, internal_outputs)) {
        PRINTF("display_external_outputs fail \n");
        return false;
    }
    int first_internal_output_index = -1;
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (bitvector_get(internal_outputs, i)) {
            first_internal_output_index = i;
            break;
        }
    }
    uint64_t first_internal_output_amount;
    if (first_internal_output_index != -1) {
        uint8_t scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
        size_t scriptPubKey_len;

        if (get_output_script_and_amount(dc,
                                         st,
                                         first_internal_output_index,
                                         scriptPubKey,
                                         &scriptPubKey_len,
                                         &first_internal_output_amount)) {
            PRINTF("First internal output amount: %d satoshi\n",
                   (uint32_t) first_internal_output_amount);
        } else {
            PRINTF("Failed to get first internal output amount\n");
        }
    } else {
        PRINTF("No internal output found\n");
    }

    if (!display_transaction(dc, first_internal_output_amount, external_input_scriptPubKey, fee)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    PRINTF("!!!!!!!1*****************  display_transaction\n");
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
    UNUSED(dc), UNUSED(st), UNUSED(tx_hashes), UNUSED(internal_inputs);

    uint8_t sighash[32];
    PRINTF("!!!!!!!1***************** Signing custom inputs %d\n", g_bbn_data.action_type);
    // compute the sighash for the special input

    if (!compute_sighash_segwitv1(dc,
                                  st,
                                  tx_hashes,
                                  &external_input_map,
                                  external_input_index,
                                  external_input_scriptPubKey,
                                  sizeof(external_input_scriptPubKey),
                                  NULL,
                                  SIGHASH_DEFAULT,
                                  sighash)) {
        PRINTF("Failed to compute the sighash\n");
        return false;
    }
    PRINTF("!!!!!!!1***************** compute_sighash_segwitv1\n");
    PRINTF("Signing parameters:\n");
    PRINTF("external_input_index: %d\n", external_input_index);
    PRINTF("magic_pubkey_path: ");
    for (size_t i = 0; i < ARRAYLEN(magic_pubkey_path); i++) {
        PRINTF("0x%08x ", magic_pubkey_path[i]);
    }
    PRINTF("\n");
    PRINTF("external_input_scriptPubKey: ");
    PRINTF_BUF(external_input_scriptPubKey, sizeof(external_input_scriptPubKey));
    PRINTF("sighash: ");
    PRINTF_BUF(sighash, sizeof(sighash));
    if (!sign_sighash_schnorr_and_yield(dc,
                                        st,
                                        external_input_index,
                                        magic_pubkey_path,
                                        ARRAYLEN(magic_pubkey_path),
                                        NULL,
                                        0,
                                        NULL,
                                        SIGHASH_DEFAULT,
                                        sighash)) {
        PRINTF("Signing failed\n");
        return false;
    }
    PRINTF("!!!!!!!1***************** sign_sighash_schnorr_and_yield\n");
    return true;
}