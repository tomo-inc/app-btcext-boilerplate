#ifndef BBN_SCRIPT_H
#define BBN_SCRIPT_H
void compute_bbn_leafhash_slasing(uint8_t *leafhash);

void compute_bbn_leafhash_unbonding(uint8_t *leafhash);

void compute_bbn_leafhash_timelock(uint8_t *leafhash);

void compute_bbn_merkle_root(uint8_t *roothash);

void compute_bip322_txid_by_message(const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *tappub,
                                    uint8_t *txid_out);

#endif  // BBN_SCRIPT_H