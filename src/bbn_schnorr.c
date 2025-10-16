#include <stdint.h>
#include <stdlib.h>

#include "lib_standard_app/crypto_helpers.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/common/psbt.h"
#include "../bitcoin_app_base/src/common/bip32.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"

#define BBN_CCMD_YIELD 0x10

static bool bbn_yield_signature(dispatcher_context_t *dc,
                                sign_psbt_state_t *st,
                                unsigned int input_index,
                                const uint8_t *pubkey,
                                uint8_t pubkey_len,
                                const uint8_t *tapleaf_hash,
                                const uint8_t *sig,
                                size_t sig_len) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // yield signature
    uint8_t cmd = BBN_CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];
    int input_index_varint_len = varint_write(buf, 0, input_index);
    dc->add_to_response(&buf, input_index_varint_len);

    // for tapscript signatures, we concatenate the (x-only) pubkey with the tapleaf hash
    uint8_t augm_pubkey_len = pubkey_len + (tapleaf_hash != NULL ? 32 : 0);

    // the pubkey is not output in version 0 of the protocol
    if (st->protocol_version >= 1) {
        dc->add_to_response(&augm_pubkey_len, 1);
        dc->add_to_response(pubkey, pubkey_len);

        if (tapleaf_hash != NULL) {
            dc->add_to_response(tapleaf_hash, 32);
        }
    }

    dc->add_to_response(sig, sig_len);

    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    return true;
}

bool bbn_sign_sighash_schnorr_and_yield(dispatcher_context_t *dc,
                                        sign_psbt_state_t *st,
                                        unsigned int input_index,
                                        const uint32_t sign_path[],
                                        size_t sign_path_len,
                                        const uint8_t *tweak_data,
                                        size_t tweak_data_len,
                                        const uint8_t *tapleaf_hash,
                                        uint8_t sighash_byte,
                                        const uint8_t sighash[static 32]) {
    uint8_t sig[64 + 1];  // extra byte for the appended sighash-type, possibly
    size_t sig_len = 0;

    cx_ecfp_public_key_t pubkey_tweaked;  // Pubkey corresponding to the key used for signing

    bool error = false;
    cx_ecfp_private_key_t private_key = {0};

    // IMPORTANT: Since we do not use any syscall that might throw an exception, it is safe to avoid
    // using the TRY/CATCH block to ensure zeroing sensitive data.

    do {  // block executed once, only to allow safely breaking out on error

        uint8_t *seckey =
            private_key.d;  // convenience alias (entirely within the private_key struct)

        if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                          sign_path,
                                          sign_path_len,
                                          &private_key,
                                          NULL) != CX_OK) {
            error = true;
            break;
        }

        if (tweak_data != NULL) {
            crypto_tr_tweak_seckey(seckey, tweak_data, tweak_data_len, seckey);
        }

        // generate corresponding public key
        unsigned int err =
            cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &pubkey_tweaked, &private_key, 1);
        if (err != CX_OK) {
            error = true;
            break;
        }

        err = cx_ecschnorr_sign_no_throw(&private_key,
                                         CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                                         CX_SHA256,
                                         sighash,
                                         32,
                                         sig,
                                         &sig_len);
        if (err != CX_OK) {
            error = true;
        }
    } while (false);

    explicit_bzero(&private_key, sizeof(private_key));

    if (error) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    if (sig_len != 64) {
        PRINTF("SIG LEN: %d\n", sig_len);
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // only append the sighash type byte if it is non-zero
    if (sighash_byte != 0x00) {
        // only add the sighash byte if not 0
        sig[sig_len++] = sighash_byte;
    }

    if (!bbn_yield_signature(
            dc,
            st,
            input_index,
            pubkey_tweaked.W + 1,  // x-only pubkey, hence take only the x-coordinate
            32,
            tapleaf_hash,
            sig,
            sig_len))
        return false;

    return true;
}