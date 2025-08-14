#ifndef BBN_TLV_H
#define BBN_TLV_H

void bbn_data_reset(void);
bool parse_tlv_data(const uint8_t *data, uint32_t data_len);

#endif  // BBN_TLV_H