#pragma once

#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"

#ifdef SCREEN_SIZE_WALLET
#define ICON_APP_HOME   C_App_64px
#define ICON_APP_ACTION C_App_64px
#else
#define ICON_APP_HOME   C_app_logo
#define ICON_APP_ACTION C_app_logo_inv
#endif

bool display_transaction(dispatcher_context_t *dc,
                         int64_t value_spent,
                         uint8_t *scriptpubkey,
                         uint64_t fee);
bool display_public_keys(dispatcher_context_t *dc,
                         uint32_t pub_count,
                         uint8_t pubkey[][32],
                         uint32_t pub_type,
                         uint32_t quorum);
bool display_cov_public_keys(dispatcher_context_t *dc,
                             uint32_t pub_count,
                             uint8_t pubkey[][32],
                             uint32_t quorum);

bool display_actions(dispatcher_context_t *dc, uint32_t action_type);

bool __attribute__((noinline)) display_external_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]);

bool get_output_script_and_amount(dispatcher_context_t *dc,
                                  sign_psbt_state_t *st,
                                  size_t output_index,
                                  uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
                                  size_t *out_scriptPubKey_len);

bool __attribute__((noinline)) display_output(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    int cur_output_index,
    int external_outputs_count,
    const uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
    size_t out_scriptPubKey_len,
    uint64_t out_amount);

bool display_timelock(dispatcher_context_t *dc, uint32_t time_lock);

bool ui_confirm_bbn_message(dispatcher_context_t *dc);