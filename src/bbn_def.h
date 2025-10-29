#ifndef BBN_DEF_H
#define BBN_DEF_H

#define INS_CUSTOM_TLV  0xbb
#define CHUNK_SIZE      64
#define MAX_CHUNK_COUNT 15

#define BBN_POLICY_NAME_SLASHING           "Consent to slashing"
#define BBN_POLICY_NAME_SLASHING_UNBONDING "Consent to unbonding slashing"
#define BBN_POLICY_NAME_STAKE_TRANSFER     "Staking transaction"
#define BBN_POLICY_NAME_UNBOND             "Unbonding"
#define BBN_POLICY_NAME_WITHDRAW           "Withdraw"
#define BBN_POLICY_NAME_BIP322_MESSAGE     "Sign message"

#define BBN_UNBONDING_MAX_FEE_CONST 9000
#define BBN_UNBONDING_MIN_FEE_CONST 1000
#define BBN_SLASHING_MAX_FEE_CONST  9000
#define BBN_SLASHING_MIN_FEE_CONST  1000

typedef enum {
    BBN_POLICY_UNKNOWN = -1,
    BBN_POLICY_SLASHING,
    BBN_POLICY_SLASHING_UNBONDING,
    BBN_POLICY_STAKE_TRANSFER,
    BBN_POLICY_UNBOND,
    BBN_POLICY_WITHDRAW,
    BBN_POLICY_BIP322,
} bbn_action_type_t;

// Atomic byte constants
#define TX_VER_BYTES 0x00, 0x00, 0x00, 0x00
#define TX_IN_CNT    0x01
#define TX_DUMMY_TXID                                                                             \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00

#define TX_VOUT_INDEX    0xff, 0xff, 0xff, 0xff
#define TX_SCRIPTSIG_LEN 0x22
#define TX_SCRIPTSIG_TAG 0x00, 0x20

#define TX_SEQ_BYTES 0x00, 0x00, 0x00, 0x00
#define TX_OUT_CNT   0x01
#define TX_OUT_VALUE 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define TX_SPK_LEN   0x22
#define TX_SPK_TAG   0x51, 0x20
#define TX_LOCKTIME  0x00, 0x00, 0x00, 0x00

// Native SegWit (P2WPKH) BIP-322 constants
#define TX_SPK_LEN_P2WPKH 0x16        // 22 bytes
#define TX_SPK_TAG_P2WPKH 0x00, 0x14  // OP_0 + 20 bytes length

#define OFFSET_MSG_HASH      44
#define OFFSET_PUBKEY        92
#define OFFSET_PUBKEY_P2WPKH 92  // P2WPKH pubkey hash offset (same as Taproot due to structure)

// Fixed parts of tx as macros
#define TX_PREFIX \
    TX_VER_BYTES, TX_IN_CNT, TX_DUMMY_TXID, TX_VOUT_INDEX, TX_SCRIPTSIG_LEN, TX_SCRIPTSIG_TAG

#define TX_MIDFIX TX_SEQ_BYTES, TX_OUT_CNT, TX_OUT_VALUE, TX_SPK_LEN, TX_SPK_TAG

#define TX_MIDFIX_P2WPKH \
    TX_SEQ_BYTES, TX_OUT_CNT, TX_OUT_VALUE, TX_SPK_LEN_P2WPKH, TX_SPK_TAG_P2WPKH

#define TX_SUFFIX TX_LOCKTIME

#define BIP32_PUBKEY_MAINNET 0x0488B21E

#define BBN_DIS_PUB_FP  1
#define BBN_DIS_PUB_COV 2

#define BBN_MAX_FP_COUNT  16
#define BBN_MAX_COV_COUNT 16

#define PRINTF_BUF(ptr, len)                              \
    do {                                                  \
        PRINTF("Buffer: ");                               \
        for (uint32_t z = 0; z < (uint32_t) (len); z++) { \
            PRINTF("%02X", (ptr)[z]);                     \
        }                                                 \
        PRINTF("\n");                                     \
    } while (0)

#endif  // BBN_DEF_H
