#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/common/psbt.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map_value.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/crypto.h"

#include "display.h"

static const uint8_t OP_RETURN_FOO[] = {0x6a, 0x03, 'F', 'O', 'O'};

#define H 0x80000000
static const uint32_t magic_pubkey_path[] = {86^H, 1^H, 99^H};


// records the value of the special input across calls
static uint64_t magic_input_value;

static bool validate_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[64],
    const uint8_t internal_outputs[64]) {

    // check that all inputs are indeed internal, except one
    int external_input_index = -1;
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
    merkleized_map_commitment_t input_map;
    if (0 > call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, external_input_index, &input_map)) {
        PRINTF("Failed to get input map\n");
        return false;
    }

    // Read the input's witness utxo
    uint8_t witness_utxo[8 + 1 + 34]; // 8 bytes amount; 1 byte length; 34 bytes P2TR Script

    if (8 + 1 + 34 != call_get_merkleized_map_value(dc,
                                                    &input_map,
                                                    (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                    sizeof((uint8_t[]){PSBT_IN_WITNESS_UTXO}),
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
    uint8_t *expected_key = xpub.compressed_pubkey + 1; // x-only key

    if (spk[0] != 0x51 || spk[1] != 0x20 || memcmp(spk + 2, expected_key, 32) != 0) {
        // the expected special input was not found
        PRINTF("Invalid scriptPubKey. Where's my magic?\n");

        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // check that all outputs are internal (that is, change), except one that is an OP_RETURN with the message "Foo"

    int external_output_index = -1;
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (bitvector_get(internal_outputs, i) == 0) {
            if (external_output_index != -1) {
                PRINTF("More than one external output found\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
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
    if (0 > call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, external_output_index, &output_map)) {
        PRINTF("Failed to get output map\n");
        return false;
    }

    // Read output amount
    uint8_t raw_amount[8];
    if (8 != call_get_merkleized_map_value(dc,
                                           &output_map,
                                           (uint8_t[]){PSBT_OUT_AMOUNT},
                                           sizeof((uint8_t[]){PSBT_OUT_AMOUNT}),
                                           raw_amount,
                                           sizeof(raw_amount))) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t amount = read_u64_le(raw_amount, 0);

    if (amount != 0) {
        PRINTF("External output has non-zero amount\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read the output's scriptPubKey
    uint8_t scriptPubKey[32];
    int result_len = call_get_merkleized_map_value(dc,
                                            &output_map,
                                            (uint8_t[]){PSBT_OUT_SCRIPT},
                                            1,
                                            scriptPubKey,
                                            sizeof(scriptPubKey));
    if (result_len != sizeof(OP_RETURN_FOO) || memcmp(scriptPubKey, OP_RETURN_FOO, sizeof(OP_RETURN_FOO)) != 0) {
        PRINTF("External output is not an OP_RETURN with the message 'FOO'\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }


    return true;
}

// hooking into a weak function
bool validate_and_display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[64],
    const uint8_t internal_outputs[64]) {

    if (!validate_transaction(dc, st, internal_inputs, internal_outputs)) {
        return false;
    }

    // the amount spent from the wallet policy (or negative if the it received more funds than it spent)
    int64_t internal_value = st->internal_inputs_total_amount - st->outputs.change_total_amount;

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    if (!display_transaction(dc, internal_value, magic_input_value, fee)) {
        return false;
    }

    return true;
}


bool sign_custom_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    tx_hashes_t *tx_hashes,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    UNUSED(dc), UNUSED(st), UNUSED(tx_hashes), UNUSED(internal_inputs);

    // TODO: sign the special input

    return true;
}