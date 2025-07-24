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

#define PRINTF_BUF(ptr, len)                              \
    do {                                                  \
        PRINTF("Buffer: ");                               \
        for (uint32_t z = 0; z < (uint32_t) (len); z++) { \
            PRINTF("%02X", (ptr)[z]);                     \
        }                                                 \
        PRINTF("\n");                                     \
    } while (0)

bool display_transaction(dispatcher_context_t *dc,
                         int64_t value_spent,
                         uint8_t* scriptpubkey,
                         uint64_t fee);
