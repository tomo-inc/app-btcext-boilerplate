#include "display.h"
#include "bbn_def.h"
#include "../bitcoin_app_base/src/ui/display.h"
#include "../bitcoin_app_base/src/ui/menu.h"
#include "io.h"
#include "nbgl_use_case.h"

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
    pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
        .item = "Transaction type",
        .value = "Babylon",
    };

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