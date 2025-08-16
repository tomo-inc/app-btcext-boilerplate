#pragma once

#include <stdint.h>
#include <stdbool.h>  // 添加这行

#ifndef BBN_SCRIPT_H
#define BBN_SCRIPT_H

bool compute_bbn_leafhash_slashing(uint8_t *leafhash);

bool compute_bbn_leafhash_unbonding(uint8_t *leafhash);

bool compute_bbn_leafhash_timelock(uint8_t *leafhash);

void compute_bbn_merkle_root(uint8_t *roothash);

void compute_bip322_txid_by_message(const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *tappub,
                                    uint8_t *txid_out);
int bbn_convert_bits(uint8_t *out,
                     size_t *outlen,
                     int outbits,
                     const uint8_t *in,
                     size_t inlen,
                     int inbits,
                     int pad);
#endif  // BBN_SCRIPT_H