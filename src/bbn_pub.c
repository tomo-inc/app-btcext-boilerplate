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
    return true;
}

void extract_full_path_from_derivation_info(const derivation_info_t *derivation_info, 
                                           uint32_t *output_path, 
                                           size_t *output_path_len) {
    // 检查路径长度
    if (derivation_info->derivation_len > MAX_BIP32_PATH_STEPS) {
        PRINTF("Path too long: %d\n", derivation_info->derivation_len);
        return;
    }
    
    // 复制完整路径
    *output_path_len = derivation_info->derivation_len;
    for (size_t i = 0; i < derivation_info->derivation_len; i++) {
        output_path[i] = derivation_info->key_origin[i];
    }
    
    // 打印路径用于调试
    PRINTF("Extracted path (len=%d): ", derivation_info->derivation_len);
    for (size_t i = 0; i < derivation_info->derivation_len; i++) {
        if (derivation_info->key_origin[i] & 0x80000000) {
            PRINTF("%d' ", derivation_info->key_origin[i] & 0x7FFFFFFF);
        } else {
            PRINTF("%d ", derivation_info->key_origin[i]);
        }
    }
    PRINTF("\n");
}