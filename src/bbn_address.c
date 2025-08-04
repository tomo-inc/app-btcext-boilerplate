#include <stdbool.h>
#include <string.h>  // 添加这行
#include <inttypes.h>
#include <stddef.h>
#include "../bitcoin_app_base/src/common/segwit_addr.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "bbn_pub.h"
#include "bbn_script.h"
#include "bbn_def.h"
#include "bbn_data.h"
#include "bbn_script.h"
#include "bbn_address.h"

bool bbn_check_staking_address(sign_psbt_state_t *st) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];

    if (!g_bbn_data.has_timelock || !g_bbn_data.has_staker_pk || !g_bbn_data.has_cov_key_list ||
        !g_bbn_data.has_cov_quorum || !g_bbn_data.has_fp_list) {
        PRINTF("Missing required data for staking address check\n");
        return false;
    }
    if (g_bbn_data.timelock == 0 || g_bbn_data.timelock > 0x7FFFFFFF) {
        PRINTF("timelock state is 0 or too large\n");
        return false;
    }
    // Compute the merkle root
    compute_bbn_merkle_root(merkle_root);
    uint8_t parity;
    // Tweak the staker public key with the merkle root
    uint8_t NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
                             0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
                             0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};
    if (crypto_tr_tweak_pubkey(NUMS_PUBKEY + 1, merkle_root, 32, &parity, tweaked_pubkey) != 0) {
        PRINTF("Failed to tweak public key\n");
        return false;
    }

    uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t out_scriptPubKey_len;
    out_scriptPubKey_len = st->outputs.output_script_lengths[0];
    memcpy(out_scriptPubKey, st->outputs.output_scripts[0], out_scriptPubKey_len);

    if (memcmp(out_scriptPubKey + 2, tweaked_pubkey, 32)) {
        PRINTF("tweak public key cmp fail\n");
        PRINTF_BUF(tweaked_pubkey, 32);
        PRINTF_BUF(out_scriptPubKey + 2, 32);
        return false;
    }
    return true;
}

bool bbn_check_slashing_address(sign_psbt_state_t *st) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];
    uint8_t staker_pk[33];
    //int32_t rv = bbn_derive_staker_pubkey_from_policy(st, 0 ,staker_pk);
    //PRINTF("bbn_derive_staker_pubkey_from_policy rv: %d\n", rv);
    //PRINTF_BUF(staker_pk, 33);
    // || !g_bbn_data.has_staker_pk
    if (!g_bbn_data.has_timelock) {
        PRINTF("Missing required data for staking address check\n");
        return false;
    }
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    if (fee < g_bbn_data.slashing_fee_limit) {
        PRINTF("inputs_total_amount=%d,total_amount=%d\n", st->inputs_total_amount, st->outputs.total_amount);
        PRINTF("Fee too low fee=%d limit=%d\n", fee, g_bbn_data.slashing_fee_limit);
        return false;
    }

    // Compute the merkle root
    compute_bbn_leafhash_timelock(merkle_root);
    uint8_t parity;
    // Tweak the staker public key with the merkle root
    uint8_t NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
                             0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
                             0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};
    if (crypto_tr_tweak_pubkey(NUMS_PUBKEY + 1, merkle_root, 32, &parity, tweaked_pubkey) != 0) {
        PRINTF("Failed to tweak public key\n");
        PRINTF_BUF(tweaked_pubkey, 32);
        return false;
    }

    uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t out_scriptPubKey_len;
    out_scriptPubKey_len = st->outputs.output_script_lengths[1];
    memcpy(out_scriptPubKey, st->outputs.output_scripts[1], out_scriptPubKey_len);

    // check the slashing output refund address
    if (memcmp(out_scriptPubKey + 2, tweaked_pubkey, 32)) {
        PRINTF("Slashing Tweaked public key:\n");
        PRINTF_BUF(tweaked_pubkey, 32);
        PRINTF("Slashing out_scriptPubKey_len 1: %d\n", out_scriptPubKey_len);
        PRINTF_BUF(out_scriptPubKey + 2, 32);
        PRINTF("tweak public key cmp fail\n");
        return false;
    }
    if (!g_bbn_data.has_slashing_address) {
        PRINTF("Slashing address not found\n");
        return false;
    }

    if (memcmp(st->outputs.output_scripts[0], g_bbn_data.slashing_address, 32)) {
        PRINTF("Slashing burn address:\n");
        PRINTF_BUF(g_bbn_data.slashing_address, 32);
        PRINTF_BUF(st->outputs.output_scripts[0], 32);
        PRINTF("tweak public key cmp fail\n");
        return false;
    }
    // to check OP_return is the first byte of the burn address script
    // however, this is only for mainnet, not for testnet due to test data

    if (BIP32_PUBKEY_VERSION == BIP32_PUBKEY_MAINNET &&
        st->outputs.output_scripts[0][0] != OP_RETURN) {
        PRINTF("Burn address script is not OP_RETURN\n");
        return false;
    }
    return true;
}

static void compute_bbn_unbond_root(uint8_t *roothash) {
    uint8_t slashing_leafhash[32];
    uint8_t timelock_leafhash[32];

    compute_bbn_leafhash_slasing(slashing_leafhash);
    compute_bbn_leafhash_timelock(timelock_leafhash);
    crypto_tr_combine_taptree_hashes(slashing_leafhash, timelock_leafhash, roothash);
}

bool bbn_check_unbond_address(sign_psbt_state_t *st) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];

    if (!g_bbn_data.has_timelock || !g_bbn_data.has_staker_pk || !g_bbn_data.has_cov_key_list ||
        !g_bbn_data.has_cov_quorum || !g_bbn_data.has_unbonding_fee_limit) {
        PRINTF("Missing required data for staking address check\n");
        return false;
    }
    if (g_bbn_data.timelock == 0 || g_bbn_data.timelock > 0x7FFFFFFF) {
        PRINTF("timelock state is 0 or too large\n");
        return false;
    }
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    if (fee < g_bbn_data.unbonding_fee_limit) {
        PRINTF("Fee too low\n");
        return false;
    }
    compute_bbn_unbond_root(merkle_root);
    uint8_t parity;

    uint8_t NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
                             0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
                             0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};

    if (crypto_tr_tweak_pubkey(NUMS_PUBKEY + 1, merkle_root, 32, &parity, tweaked_pubkey) != 0) {
        PRINTF("Failed to tweak public key\n");
        return false;
    }

    uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t out_scriptPubKey_len;
    out_scriptPubKey_len = st->outputs.output_script_lengths[0];
    memcpy(out_scriptPubKey, st->outputs.output_scripts[0], out_scriptPubKey_len);

    if (memcmp(out_scriptPubKey + 2, tweaked_pubkey, 32)) {
        PRINTF("Tweaked public key:\n");
        // PRINTF_BUF(tweaked_pubkey, 32);
        PRINTF("out_scriptPubKey_len: %d\n", out_scriptPubKey_len);
        // PRINTF_BUF(out_scriptPubKey + 2, 32);
        PRINTF("bbn_check_unbond tweak public key cmp fail\n");
        return false;
    }
    return true;
}

bool bbn_check_message(void) {
    uint8_t message[64] = {0};
    size_t message_len = 0;
    char message_str[128] = {0};

    if (!g_bbn_data.has_message || !g_bbn_data.has_fp_list || !g_bbn_data.has_staker_pk ||
        !g_bbn_data.has_txid) {
        PRINTF("Missing required data for message check\n");
        return false;
    }

    compute_bip322_txid_by_message(g_bbn_data.message,
                                   g_bbn_data.message_len,
                                   g_bbn_data.fp_list[0],
                                   g_bbn_data.txid);
    if (memcmp(g_bbn_data.txid, g_bbn_data.staker_pk, 32) != 0) {
        PRINTF("txid\n");
        PRINTF("st->psbt_staker_pk\n");
        return false;
    }

    bbn_convert_bits(message, &message_len, 5, g_bbn_data.message, g_bbn_data.message_len, 8, 1);
    bech32_encode(message_str,
                  (const char *) "bbn",
                  message,
                  message_len,
                  BECH32_ENCODING_BECH32);  // bech32 encode the message

    // if (!ui_confirm_bbn_message(dc, message_str, "message")) {
    //     PRINTF("message_str %s\n", message_str);
    //     // PRINTF_BUF(message_str, 64);
    //     SEND_SW(dc, SW_DENY);
    //     return false;
    // }
    return true;
}