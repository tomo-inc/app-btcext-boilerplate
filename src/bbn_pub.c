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

bool bbn_derive_pubkey(uint32_t *bip32_path,
                       uint8_t bip32_path_len,
                       uint32_t bip32_pubkey_version,
                       uint8_t *out_pubkey) {
    // uint8_t spk[32] = {
    // 0xdc, 0x8d, 0x2f, 0x9e, 0xff, 0x0c, 0x4f, 0x4d,
    // 0xbd, 0xe0, 0x70, 0xa4, 0x8e, 0x33, 0x0e, 0xfc,
    // 0x90, 0x8b, 0x62, 0xa7, 0x66, 0x56, 0x8d, 0x91,
    // 0xe6, 0x58, 0xf2, 0x84, 0xb3, 0x24, 0xb8, 0x78
    // };
    
    // memcpy(staker_pk_out, spk, 32);
    // PRINTF("Using hardcoded staker public key: ");
    // PRINTF_BUF(staker_pk_out, 32);
    // return true;

    serialized_extended_pubkey_t xpub;
    if (0 > get_extended_pubkey_at_path(bip32_path,
                                        bip32_path_len,
                                        BIP32_PUBKEY_VERSION,
                                        &xpub)) {
        PRINTF("Failed getting bip32 pubkey\n");
        return false;
    }
    uint8_t *expected_key = xpub.compressed_pubkey + 1;
    memcpy(out_pubkey, expected_key, 32);
    PRINTF("bbn_derive_pubkey out_pubkey: ");
    PRINTF_BUF(out_pubkey, 32);
    g_bbn_data.has_staker_pk = true;
    return true;
}