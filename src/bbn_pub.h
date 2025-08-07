
#include "../bitcoin_app_base/src/common/bip32.h"

// 从 sign_psbt.c 复制的类型定义
typedef struct {
    uint32_t fingerprint;
    size_t derivation_len;
    uint32_t key_origin[MAX_BIP32_PATH_STEPS];
} derivation_info_t;

bool bbn_derive_pubkey(uint32_t *bip32_path,
                       uint8_t bip32_path_len,
                       uint32_t bip32_pubkey_version,
                       uint8_t *out_pubkey);

void extract_full_path_from_derivation_info(const derivation_info_t *derivation_info, 
                                           uint32_t *output_path, 
                                           size_t *output_path_len);