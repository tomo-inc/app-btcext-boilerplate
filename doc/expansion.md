# Expansion

| Component | Taproot Address | Native SegWit Address |
|-----------|-----------------|----------------------|
| **Toolkit** | Taproot selected | Native segwit selected |
| **Path Set** | 86' | 84' |
| **Contract** | sign-btc-staking-expansion-transaction | sign-btc-staking-expansion-transaction |
| **UTXO[0]** | stake-output, unlock: tr script path, pubkey: 86' | stake-output, unlock: tr script path, pubkey: 86' |
| **UTXO[1]** | normal tr, unlock: tr key path | normal ns, unlock: sign |
| **Action** | expansion | expansion |
| **Policy Items** | as staking | as staking |
| **Output** | same staking address | same staking address |
| **Value** | >=orignal | >=orignal  |
| **Input[0] Sign** | 86' schnorr, script: unbonding | 84' schnorr, script: unbonding |
| **Input[1] Sign** | 86' | 84' ecdsa | 
