#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/crypto.h"

// hooking into a weak function
bool validate_and_display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[64]) {
    UNUSED(st), UNUSED(internal_outputs);

    // yolo
    return true;
}