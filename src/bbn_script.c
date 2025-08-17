
#include <stdbool.h>
#include <inttypes.h>
#include <stddef.h>
#include "../bitcoin_app_base/src/common/segwit_addr.h"
#include "../bitcoin_app_base/src/crypto.h"
#include "../bitcoin_app_base/src/common/merkle.h"
#include "bbn_def.h"
#include "bbn_data.h"
#include "bbn_script.h"

static const uint8_t BIP0322_msghash_tag[] = {'B', 'I', 'P', '0', '3', '2', '2', '-',
                                              's', 'i', 'g', 'n', 'e', 'd', '-', 'm',
                                              'e', 's', 's', 'a', 'g', 'e'};

int bbn_convert_bits(uint8_t *out,
                     size_t *outlen,
                     int outbits,
                     const uint8_t *in,
                     size_t inlen,
                     int inbits,
                     int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t) 1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

static void bbn_leafhash_compute(uint8_t *tapscript, int tapscript_len, uint8_t *leafhash) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);
    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);
    crypto_hash_update(&hash_context.header, tapscript, tapscript_len);
    crypto_hash_digest(&hash_context.header, leafhash, 32);
}

static int encode_minimal_push(uint32_t value, uint8_t *buffer) {
    if (value == 0) {
        buffer[0] = 0x00;
        return 1;
    }

    if (value >= 1 && value <= 15) {
        buffer[0] = 0x50 + value;
        return 1;
    }

    int size = 0;
    int is_negative = (value < 0);
    uint32_t abs_value = (is_negative) ? -value : value;

    while (abs_value) {
        buffer[size++] = abs_value & 0xFF;
        abs_value >>= 8;
    }

    if (buffer[size - 1] & 0x80) {
        buffer[size++] = is_negative ? 0x80 : 0x00;
    } else if (is_negative) {
        buffer[size - 1] |= 0x80;
    }

    return size;
}

bool compute_bbn_leafhash_slashing(uint8_t *leafhash) {
    uint8_t tapscript[1024] = {0};
    int offset = 0;

    tapscript[offset++] = 0x20;
    if (g_bbn_data.has_staker_pk)
        memcpy(tapscript + offset, g_bbn_data.staker_pk, 32);
    else
        return false;

    offset += 32;
    tapscript[offset++] = 0xad;
    tapscript[offset++] = 0x20;
    if (g_bbn_data.has_fp_list) {
        if (g_bbn_data.fp_count > MAX_FP_COUNT) {
            return false;
        }
        for (int i = 0; i < g_bbn_data.fp_count; i++) {
            memcpy(tapscript + offset, g_bbn_data.fp_list[i], 32);
            offset += 32;
            tapscript[offset++] = 0xad;  // TODO confirm multi FP is single sig or multi-sig
        }
    } else {
        return false;
    }
    if (g_bbn_data.has_cov_key_list) {
        if (g_bbn_data.cov_key_count > MAX_COV_KEY_COUNT) {
            return false;
        }
        for (int i = 0; i < g_bbn_data.cov_key_count; i++) {
            tapscript[offset++] = 0x20;
            memcpy(tapscript + offset, g_bbn_data.cov_key_list[i], 32);
            offset += 32;
            if (i == 0)
                tapscript[offset++] = 0xac;
            else
                tapscript[offset++] = 0xba;
        }
    } else {
        return false;
    }
    if (g_bbn_data.has_cov_quorum)
        tapscript[offset++] = 0x50 + g_bbn_data.cov_quorum;
    else
        return false;

    tapscript[offset++] = 0x9c;
    PRINTF("tapscript length: %d\n", offset);
    PRINTF_BUF(tapscript, offset);
    // Compute leaf hash
    bbn_leafhash_compute(tapscript, offset, leafhash);
    return true;
}

bool compute_bbn_leafhash_unbonding(uint8_t *leafhash) {
    uint8_t tapscript[1024] = {0};
    int offset = 0;

    tapscript[offset++] = 0x20;
    if (g_bbn_data.has_staker_pk)
        memcpy(tapscript + offset, g_bbn_data.staker_pk, 32);
    else
        return false;

    offset += 32;
    tapscript[offset++] = 0xad;

    if (g_bbn_data.has_cov_key_list) {
        if (g_bbn_data.cov_key_count > MAX_COV_KEY_COUNT) {
            return false;
        }
        for (int i = 0; i < g_bbn_data.cov_key_count; i++) {
            tapscript[offset++] = 0x20;
            memcpy(tapscript + offset, g_bbn_data.cov_key_list[i], 32);
            offset += 32;
            if (i == 0)
                tapscript[offset++] = 0xac;
            else
                tapscript[offset++] = 0xba;
        }
    } else {
        return false;
    }
    if (g_bbn_data.has_cov_quorum)
        tapscript[offset++] = 0x50 + g_bbn_data.cov_quorum;
    else
        return false;

    tapscript[offset++] = 0x9c;

    // Compute leaf hash
    bbn_leafhash_compute(tapscript, offset, leafhash);
    return true;
}

bool compute_bbn_leafhash_timelock(uint8_t *leafhash) {
    PRINTF("compute_bbn_leafhash_timelock\n");

    uint8_t tapscript[1024] = {0};
    int offset = 0;

    PRINTF("compute_bbn_leafhash_timelock staker_pk:\n");
    PRINTF_BUF(g_bbn_data.staker_pk, 32);

    tapscript[offset++] = 0x20;
    if (g_bbn_data.has_staker_pk)
        memcpy(tapscript + offset, g_bbn_data.staker_pk, 32);
    else {
        PRINTF("No timelock has_staker_pk\n");
        return false;
    }

    offset += 32;
    tapscript[offset++] = 0xad;

    uint8_t value_buffer[4];
    if (g_bbn_data.has_timelock) {
        int len = encode_minimal_push(g_bbn_data.timelock, value_buffer);
        if (g_bbn_data.timelock > 15) tapscript[offset++] = len;
        memcpy(tapscript + offset, value_buffer, len);
        offset += len;
        tapscript[offset++] = 0xb2;
    } else {
        PRINTF("No timelock found\n");
        return false;
    }
    PRINTF("timelock: %d\n", (uint32_t) g_bbn_data.timelock);
    PRINTF("tap length: %d\n", offset);
    PRINTF_BUF(tapscript, offset);
    bbn_leafhash_compute(tapscript, offset, leafhash);
    return true;
}

void compute_bbn_merkle_root(uint8_t *roothash) {
    uint8_t slashing_leafhash[32];
    uint8_t unbonding_leafhash[32];
    uint8_t timelock_leafhash[32];

    compute_bbn_leafhash_slashing(slashing_leafhash);
    compute_bbn_leafhash_unbonding(unbonding_leafhash);
    compute_bbn_leafhash_timelock(timelock_leafhash);

    uint8_t branch_hash[32];
    crypto_tr_combine_taptree_hashes(unbonding_leafhash, timelock_leafhash, branch_hash);

    crypto_tr_combine_taptree_hashes(slashing_leafhash, branch_hash, roothash);
}

void compute_bip322_txid_by_message(const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *tappub,
                                    uint8_t *txid_out) {
    uint8_t tx[] = {TX_PREFIX, TX_DUMMY_TXID, TX_MIDFIX, TX_DUMMY_TXID, TX_SUFFIX};
    cx_sha256_t sighash_context, txhash_context, txid_context;
    uint8_t hash[32];
    uint8_t converted_5bit[32 * 2] = {0};
    size_t datalen = 0;
    char converted_message[32 * 4] = {0};
    PRINTF("compute_bip322_txid_by_message %d\n", message_len);
    PRINTF("message: ");
    PRINTF_BUF(message, message_len);
    PRINTF("tappub: ");
    PRINTF_BUF(tappub, 32);

    crypto_tr_tagged_hash_init(&sighash_context, BIP0322_msghash_tag, sizeof(BIP0322_msghash_tag));

    bbn_convert_bits(converted_5bit, &datalen, 5, message, message_len, 8, 1);
    bech32_encode(converted_message,
                  (const char *) "bbn",
                  converted_5bit,
                  datalen,
                  BECH32_ENCODING_BECH32);  // bech32 encode the message
    crypto_hash_update(&sighash_context.header, converted_message, strlen(converted_message));
    crypto_hash_digest(&sighash_context.header, hash, 32);

    memcpy(tx + OFFSET_MSG_HASH, hash, 32);
    memcpy(tx + OFFSET_PUBKEY, tappub, 32);

    cx_sha256_init(&txhash_context);
    crypto_hash_update(&txhash_context.header, tx, sizeof(tx));
    crypto_hash_digest(&txhash_context.header, hash, 32);
    cx_sha256_init(&txid_context);
    crypto_hash_update(&txid_context.header, hash, 32);
    crypto_hash_digest(&txid_context.header, txid_out, 32);
}