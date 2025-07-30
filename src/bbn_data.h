#ifndef BBN_DATA_DEF_H
#define BBN_DATA_DEF_H

#define TAG_ACTION_TYPE         0x77
#define TAG_FP_COUNT            0xf9
#define TAG_FP_LIST             0xf8
#define TAG_COV_KEY_COUNT       0xc0
#define TAG_COV_KEY_LIST        0xc1
#define TAG_STAKER_PK           0x51
#define TAG_COV_QUORUM          0x01
#define TAG_TIMELOCK            0x71
#define TAG_SLASHING_FEE_LIMIT  0xfe
#define TAG_UNBONDING_FEE_LIMIT 0xff

// Action Type定义
#define ACTION_STAKING            1
#define ACTION_UNBOND             2
#define ACTION_SLASHING           3
#define ACTION_UNBONDING_SLASHING 4
#define ACTION_WITHDRAW           5
#define ACTION_SIGN_MESSAGE       6

#define MAX_FP_COUNT      16
#define MAX_COV_KEY_COUNT 16

typedef struct {
    // Action Type
    bool has_action_type;
    uint8_t action_type;

    // Finality Provider
    bool has_fp_count;
    uint8_t fp_count;
    bool has_fp_list;
    uint8_t fp_list[MAX_FP_COUNT][32];

    // Covenant Keys
    bool has_cov_key_count;
    uint8_t cov_key_count;
    bool has_cov_key_list;
    uint8_t cov_key_list[MAX_COV_KEY_COUNT][32];

    // Staker Public Key
    bool has_staker_pk;
    uint8_t staker_pk[32];

    // Covenant Quorum
    bool has_cov_quorum;
    uint8_t cov_quorum;

    // Timelocks
    bool has_timelock;
    uint64_t timelock;

    // Fee Limits
    bool has_slashing_fee_limit;
    uint64_t slashing_fee_limit;
    bool has_unbonding_fee_limit;
    uint64_t unbonding_fee_limit;

} bbn_data_t;

// 全局变量声明
extern bbn_data_t g_bbn_data;

#endif  // BBN_DATA_DEF_H