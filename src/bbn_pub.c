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

static bool get_derivation_path_from_keyexpr(sign_psbt_state_t *st,
                                             uint32_t input_index,
                                             uint32_t **path_out,
                                             size_t *path_len_out) {
    // 检查是否有内部密钥表达式
    if (st->n_internal_key_expressions == 0) {
        PRINTF("No internal key expressions available\n");
        return false;
    }

    // 获取第一个内部密钥表达式
    keyexpr_info_t *keyexpr = &st->internal_key_expressions[0];
    
    // 检查密钥派生信息
    if (keyexpr->key_derivation_length > 0) {
        // 使用密钥表达式中的派生路径
        static uint32_t full_path[MAX_BIP32_PATH_STEPS];
        size_t base_len = keyexpr->key_derivation_length;
        
        if (base_len > MAX_BIP32_PATH_STEPS) {
            PRINTF("Derivation path too long\n");
            return false;
        }
        
        // 复制派生路径
        memcpy(full_path, keyexpr->key_derivation, base_len * sizeof(uint32_t));
        
        *path_out = full_path;
        *path_len_out = base_len;
        
        PRINTF("Using keyexpr derivation path, length: %zu\n", base_len);
        return true;
    }

    PRINTF("No key derivation info found for input %d\n", input_index);
    return false;
}

static bool get_standard_taproot_path(uint32_t account,
                                      uint32_t change,
                                      uint32_t address_index,
                                      uint32_t **path_out,
                                      size_t *path_len_out) {
    // BIP86 Taproot: m/86'/0'/0'/change/address_index
    static uint32_t path[5];

    path[0] = 86 | 0x80000000;       // 86' (hardened)
    path[1] = 0 | 0x80000000;        // 0' (BTC, hardened)
    path[2] = account | 0x80000000;  // account' (hardened)
    path[3] = change;                // change (0 or 1)
    path[4] = address_index;         // address_index

    *path_out = path;
    *path_len_out = 5;

    return true;
}

static bool derive_pubkey_from_serialized_xpub(const serialized_extended_pubkey_t *ext_pubkey,
                                               const uint32_t *derivation_path,
                                               size_t path_len,
                                               uint8_t *pubkey_out) {
    // 检查扩展公钥的有效性
    if (ext_pubkey->compressed_pubkey[0] != 0x02 && ext_pubkey->compressed_pubkey[0] != 0x03) {
        PRINTF("Invalid compressed public key format\n");
        return false;
    }
    
    // 如果没有派生路径，直接使用压缩公钥
    if (path_len == 0) {
        memcpy(pubkey_out, ext_pubkey->compressed_pubkey + 1, 32);
        PRINTF("Using base public key (no derivation)\n");
        return true;
    }
    
    // 对于有派生路径的情况，需要进行派生
    serialized_extended_pubkey_t derived_pubkey;
    memcpy(&derived_pubkey, ext_pubkey, sizeof(serialized_extended_pubkey_t));
    
    // 逐级派生（只支持非hardened路径）
    for (size_t i = 0; i < path_len; i++) {
        uint32_t index = derivation_path[i];
        
        // 检查是否是 hardened 派生
        if (index & 0x80000000) {
            PRINTF("Cannot derive hardened path from public key at level %zu\n", i);
            return false;
        }
        
        // 使用正确的 BIP32 函数签名
        serialized_extended_pubkey_t child_pubkey;
        if (bip32_CKDpub(&derived_pubkey, index, &child_pubkey, NULL) != 0) {
            PRINTF("Failed to derive public key at level %zu, index %u\n", i, index);
            return false;
        }
        
        // 更新派生结果
        memcpy(&derived_pubkey, &child_pubkey, sizeof(serialized_extended_pubkey_t));
    }
    
    // 提取 32 字节的 x 坐标（去掉压缩标志）
    memcpy(pubkey_out, derived_pubkey.compressed_pubkey + 1, 32);
    
    PRINTF("Successfully derived staker pubkey: ");
    PRINTF_BUF(pubkey_out, 32);
    
    return true;
}

bool bbn_derive_staker_pubkey_from_policy(sign_psbt_state_t *st,
                                          uint32_t input_index,
                                          uint8_t *staker_pk_out) {
    uint32_t *derivation_path = NULL;
    size_t path_len = 0;

    // 方法1：尝试从内部密钥表达式获取派生路径
    if (get_derivation_path_from_keyexpr(st, input_index, &derivation_path, &path_len)) {
        PRINTF("Using derivation path from key expression\n");
    }
    // 方法2：使用标准 Taproot 路径
    else {
        PRINTF("Using standard Taproot derivation path\n");
        get_standard_taproot_path(0, 0, input_index, &derivation_path, &path_len);
    }

    // 检查是否有内部密钥表达式和钱包头
    if (st->n_internal_key_expressions == 0 || st->wallet_header.n_keys == 0) {
        PRINTF("No internal key expressions or wallet keys available\n");
        return false;
    }
    
    // 使用第一个内部密钥表达式的公钥
    keyexpr_info_t *keyexpr = &st->internal_key_expressions[0];
    
    // 从扩展公钥派生最终公钥
    return derive_pubkey_from_serialized_xpub(&keyexpr->pubkey,
                                              derivation_path,
                                              path_len,
                                              staker_pk_out);
}