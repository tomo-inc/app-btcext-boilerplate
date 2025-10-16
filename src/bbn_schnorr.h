
bool bbn_sign_sighash_schnorr_and_yield(dispatcher_context_t *dc,
                                        sign_psbt_state_t *st,
                                        unsigned int input_index,
                                        const uint32_t sign_path[],
                                        size_t sign_path_len,
                                        const uint8_t *tweak_data,
                                        size_t tweak_data_len,
                                        const uint8_t *tapleaf_hash,
                                        uint8_t sighash_byte,
                                        const uint8_t sighash[static 32]);