#include "../bitcoin_app_base/src/ui/display.h"
#include "../bitcoin_app_base/src/ui/menu.h"
#include "../bitcoin_app_base/src/common/psbt.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map.h"
#include "io.h"
#include "nbgl_use_case.h"
#include "bbn_def.h"
#include "display.h"

#define MAX_N_PAIRS 4
static const char *confirmed_status;  // text displayed in confirmation page (after long press)
static const char *rejected_status;   // text displayed in rejection page (after reject confirmed)

static void ux_flow_response_true(void) {
    set_ux_flow_response(true);
}

static void ux_flow_response_false(void) {
    set_ux_flow_response(false);
}

static void review_choice(bool approved) {
    set_ux_flow_response(approved);  // sets the return value of io_ui_process

    if (approved) {
        // nothing to do in this case; after signing, the responsibility to show the main menu
        // goes back to the base app's handler
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}
static void status_operation_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseStatus(rejected_status, false, ui_menu_main);
}

static void status_operation_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseStatus(confirmed_status, true, ui_menu_main);
    } else {
        status_operation_cancel();
    }
}



bool display_public_keys(dispatcher_context_t *dc,
                         uint32_t pub_count,
                         uint8_t pubkey[][32],
                         uint32_t pub_type,
                         uint32_t quorum) {
    nbgl_layoutTagValue_t pairs[16];
    nbgl_layoutTagValueList_t pairList;

    confirmed_status = "Action\nconfirmed";
    rejected_status = "Action rejected";

    char hexbuf[BBN_MAX_FP_COUNT][65];
    char labels[BBN_MAX_FP_COUNT][8];
    char quorum_value[8];
    int n_pairs = 0;

    if(pub_type == BBN_DIS_PUB_COV){
        snprintf(quorum_value, sizeof(quorum_value), "%d", quorum);                        
        pairs[n_pairs].item = "Covenant quorum";
        pairs[n_pairs].value = quorum_value;
        n_pairs++;   
    }
                         
    for (uint32_t i = 0; i < pub_count; i++) {
         for (uint32_t j = 0; j < 32; j++) { // 假设每个 pubkey 是 32 字节
            snprintf(&hexbuf[i][j * 2], 3, "%02X", pubkey[i][j]);
        }
        hexbuf[i][64] = '\0'; // 确保字符串以 null 结尾
        snprintf(labels[i], sizeof(labels[i]), "Pub %u", i + 1);
        pairs[n_pairs] = (nbgl_layoutTagValue_t) {
            .item = labels[i],
            .value = hexbuf[i],
        };
        n_pairs++;
    }

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = n_pairs;
    pairList.pairs = pairs;
    PRINTF("Reviewing public keys: %d\n", n_pairs);
    if(pub_type == BBN_DIS_PUB_COV) {
         nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &pairList,
                            &ICON_APP_ACTION,
                            "Covenant public keys",
                            NULL,
                            "Confirm covenant\npublic keys",
                            status_operation_callback);
    }else {
         nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &pairList,
                            &ICON_APP_ACTION,
                            "Finality public keys",
                            NULL,
                            "Confirm finality\npublic keys",
                            status_operation_callback);
    }
   

    // blocking call until the user approves or rejects the transaction
    bool result = io_ui_process(dc);
    if (!result) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

bool display_transaction(dispatcher_context_t *dc,
                         int64_t value_spent,
                         uint8_t *scriptpubkey,
                         uint64_t fee) {
    nbgl_layoutTagValue_t pairs[4];
    nbgl_layoutTagValueList_t pairList;

    // format value_spent
    char value_str[32], addr_str[64], fee_str[32];
    uint64_t value_spent_abs = value_spent < 0 ? -value_spent : value_spent;
    format_sats_amount(COIN_COINID_SHORT, value_spent_abs, value_str);
    format_sats_amount(COIN_COINID_SHORT, fee, fee_str);
    // Convert scriptpubkey to address string

    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    if (!format_script(scriptpubkey, 34, output_description)) {
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }

    int n_pairs = 0;

    if (value_spent >= 0) {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
            .item = "Value spent",
            .value = value_str,
        };
    } else {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
            .item = "Value received",
            .value = value_str,
        };
    }

    pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
        .item = "Address",
        .value = output_description,
    };

    pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
        .item = "Fee",
        .value = fee_str,
    };

    assert(n_pairs <= MAX_N_PAIRS);

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = n_pairs;
    pairList.pairs = pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &ICON_APP_ACTION,
                       "Review transaction\nBabylon Staking",
                       NULL,
                       "Sign transaction\nFor Babylon Staking",
                       review_choice);

    // blocking call until the user approves or rejects the transaction
    bool result = io_ui_process(dc);
    if (!result) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

bool display_actions(dispatcher_context_t *dc, uint32_t action_type) {
    confirmed_status = "Action\nconfirmed";
    rejected_status = "Action rejected";
    static char action_name[64];
    static char action_name_approve[64];
    switch ((bbn_action_type_t)action_type) {
        case BBN_POLICY_SLASHING:
            strncpy(action_name, BBN_POLICY_NAME_SLASHING, sizeof(action_name) - 1);
            break;
        case BBN_POLICY_SLASHING_UNBONDING:
            strncpy(action_name, BBN_POLICY_NAME_SLASHING_UNBONDING, sizeof(action_name) - 1);
            break;
        case BBN_POLICY_STAKE_TRANSFER:
            strncpy(action_name, BBN_POLICY_NAME_STAKE_TRANSFER, sizeof(action_name) - 1);
            break;
        case BBN_POLICY_UNBOND:
            strncpy(action_name, BBN_POLICY_NAME_UNBOND, sizeof(action_name) - 1);
            break;
        case BBN_POLICY_WITHDRAW:
            strncpy(action_name, BBN_POLICY_NAME_WITHDRAW, sizeof(action_name) - 1);
            break;
        case BBN_POLICY_BIP322:
            strncpy(action_name, BBN_POLICY_NAME_BIP322_MESSAGE, sizeof(action_name) - 1);
            break;
        default:
            strncpy(action_name, "Unknown action", sizeof(action_name) - 1);
            break;
    }
    action_name[sizeof(action_name) - 1] = '\0';

    // 构造 "Approve ..." 字符串
    snprintf(action_name_approve, sizeof(action_name_approve), "Approve %s", action_name);

    static nbgl_layoutTagValue_t pair;
    static nbgl_layoutTagValueList_t pairList;
    pair.item = "Action name";
    pair.value = action_name;
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = &pair;
    PRINTF("Reviewing action: %s\n", action_name);
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                       &pairList,
                       &ICON_APP_ACTION,
                       "Babylon action",
                       NULL,
                       action_name_approve,
                       status_operation_callback);

    // blocking call until the user approves or rejects the action
    bool result = io_ui_process(dc);
    if (!result) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

bool __attribute__((noinline)) display_external_outputs(
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
            if (!display_output(dc,
                                st,
                                cur_output_index,
                                external_outputs_count,
                                out_scriptPubKey,
                                out_scriptPubKey_len,
                                out_amount)) {
                return false;
            }
        }
    }

    return true;
}

bool get_output_script_and_amount(
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
                                                   (uint8_t[]){PSBT_OUT_AMOUNT},
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
                                               (uint8_t[]){PSBT_OUT_SCRIPT},
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

bool __attribute__((noinline))
display_output(dispatcher_context_t *dc,
               sign_psbt_state_t *st,
               int cur_output_index,
               int external_outputs_count,
               const uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
               size_t out_scriptPubKey_len,
               uint64_t out_amount) {
    (void) cur_output_index;

    // show this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    // chester
    // if it is the sign message in BIP322
    // to avoid it is mis-used(attacked) for normal transaction
    // we check amount=0, address=OP_RETURN
    // if (st->bbn_action_type == BBN_POLICY_BIP322) {
    //     if (!is_opreturn(out_scriptPubKey, out_scriptPubKey_len) || out_amount != 0) {
    //         SEND_SW(dc, SW_NOT_SUPPORTED);
    //         return false;
    //     }
    // }

    if (!format_script(out_scriptPubKey, out_scriptPubKey_len, output_description)) {
        PRINTF("Invalid or unsupported script for output %d\n", cur_output_index);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }

    // Show address to the user
    if (!ui_validate_output(dc,
                            external_outputs_count,
                            st->n_external_outputs,
                            output_description,
                            COIN_COINID_SHORT,
                            out_amount)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}