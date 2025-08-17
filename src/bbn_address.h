#pragma once

#include <stdint.h>
#include <stdbool.h>  // 添加这行

#ifndef BBN_ADDRESS_H
#define BBN_ADDRESS_H

bool bbn_check_staking_address(sign_psbt_state_t *st);

bool bbn_check_slashing_address(sign_psbt_state_t *st, uint8_t *staker_pk);

bool bbn_check_unbond_address(sign_psbt_state_t *st);

bool bbn_check_message(uint8_t *psbt_txid);

#endif  // BBN_ADDRESS_H