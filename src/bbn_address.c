#include <stdbool.h>
#include <inttypes.h>
#include "bbn_script.h"
#include "bbn_address.h"

bool bbn_check_staking_address(void) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];

    // to check uint32_t psbt_timelock here
    // if 0 or negative, return false
    // to advoid BBN-#04 Potential buffer overflow
    if (st->psbt_timelock == 0 || st->psbt_timelock > 0x7FFFFFFF) {
        PRINTF("timelock state is 0 or negtive\n");
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

bool bbn_check_slashing_address(void) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];

    get_fee_from_desciptor(st);
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    if (fee < st->psbt_fee) {
        PRINTF("Fee too low\n");
        return false;
    }

    // Compute the merkle root
    compute_bbn_leafhash_timelock(st, merkle_root);
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

    // check the burn address
    unsigned int cov_count = count_psbt_covenant_pk_state(st->psbt_covenant_pk_state);

    uint8_t *slashPkScript = st->psbt_covenant_pk[cov_count - 2];
    if (slashPkScript == NULL) {
        PRINTF("missing burn address null\n");
        return false;
    }
    if (memcmp(st->outputs.output_scripts[0], slashPkScript, 32)) {
        PRINTF("Slashing burn address:\n");
        PRINTF_BUF(slashPkScript, 32);
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

    compute_bbn_leafhash_slasing(st, slashing_leafhash);
    compute_bbn_leafhash_timelock(st, timelock_leafhash);
    crypto_tr_combine_taptree_hashes(slashing_leafhash, timelock_leafhash, roothash);
}

bool bbn_check_unbond_address(void) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];
    if (st->psbt_timelock == 0) {
        PRINTF("timelock state is 0\n");
        return false;
    }
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    get_fee_from_desciptor(st);
    if (fee != st->psbt_fee) {
        PRINTF("unbond fee mismatch\n");
        return false;
    }
    compute_bbn_unbond_root(st, merkle_root);
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

static bool bbn_check_message(void) {
    uint8_t txid[32];
    uint8_t message[64] = {0};
    size_t message_len = 0;
    char message_str[128] = {0};

    compute_bip322_txid_by_message(st->psbt_leafhash + 1,
                                   st->psbt_leafhash_state,
                                   st->psbt_finality_pk,
                                   txid);
    if (memcmp(txid, st->psbt_staker_pk, 32) != 0) {
        PRINTF("txid\n");
        // PRINTF_BUF(txid, 32);
        PRINTF("st->psbt_staker_pk\n");
        // PRINTF_BUF(st->psbt_staker_pk, 32);
        SEND_SW(dc, SW_DENY);
        return false;
    }

    convert_bits(message, &message_len, 5, st->psbt_leafhash + 1, st->psbt_leafhash_state, 8, 1);
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