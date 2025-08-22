#include <stdbool.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>  // 添加这个头文件
#include "../bitcoin_app_base/src/common/segwit_addr.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/common/bip32.h"
#include "bbn_script.h"
#include "bbn_def.h"
#include "bbn_data.h"

bool bbn_derive_pubkey(uint32_t *bip32_path, uint8_t bip32_path_len, uint8_t *out_pubkey) {
    serialized_extended_pubkey_t xpub;
    if (0 > get_extended_pubkey_at_path(bip32_path, bip32_path_len, BIP32_PUBKEY_VERSION, &xpub)) {
        PRINTF("Failed getting bip32 pubkey\n");
        return false;
    }
    uint8_t *expected_key = xpub.compressed_pubkey + 1;
    memcpy(out_pubkey, expected_key, 32);
    return true;
}
