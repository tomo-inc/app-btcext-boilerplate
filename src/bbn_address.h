#ifndef BBN_ADDRESS_H
#define BBN_ADDRESS_H

bool bbn_check_staking_address(sign_psbt_state_t *st);

bool bbn_check_slashing_address(sign_psbt_state_t *st);

bool bbn_check_unbond_address(sign_psbt_state_t *st);

bool bbn_check_message(void);

#endif  // BBN_ADDRESS_H