#include "display.h"

#include "../bitcoin_app_base/src/ui/display.h"
#include "../bitcoin_app_base/src/ui/menu.h"
#include "io.h"
#include "nbgl_use_case.h"

#define MAX_N_PAIRS 16

static void review_choice(bool approved) {
    set_ux_flow_response(approved);  // sets the return value of io_ui_process

    if (approved) {
        // nothing to do in this case; after signing, the responsibility to show the main menu
        // goes back to the base app's handler
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

bool display_public_keys(dispatcher_context_t *dc,
                         uint32_t pub_count,
                         uint8_t pubkey[][65],
                         uint32_t pub_type) {
    nbgl_layoutTagValue_t pairs[4];
    nbgl_layoutTagValueList_t pairList;

    char hexbuf[16][65];
    char labels[16][8];
    int n_pairs = 0;
    for (uint32_t i = 0; i < pub_count; i++) {
        memcpy(hexbuf[i], pubkey[i], 64);
        hexbuf[i][64] = '\0';
        labels[i][0] = 'P';
        labels[i][1] = 'u';
        labels[i][2] = 'b';
        labels[i][3] = ' ';
        labels[i][4] = '1' + i;
        labels[i][5] = '\0';
        pairs[n_pairs].item = labels[i];
        pairs[n_pairs].value = hexbuf[i];
        n_pairs++;
    }

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
