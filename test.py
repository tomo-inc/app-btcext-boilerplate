from ledger_bitcoin import Chain, TransportClient, WalletPolicy
from ledger_bitcoin.client import NewClient as AppClient
from ledger_bitcoin.psbt import PSBT


CLA_APP = 0xE1
INS_CUSTOM_XOR = 128

if __name__ == '__main__':
    transport = TransportClient()
    client = AppClient(transport, chain=Chain.TEST)

    # Tests a custom APDU. A real application should implement a
    # custom client instead of using raw APDUs.
    data = bytes([1, 2, 3, 4, 5])
    res = transport.apdu_exchange(CLA_APP, INS_CUSTOM_XOR, data, 0, 0)
    assert res == bytes([1 ^ 2 ^ 3 ^ 4 ^ 5])

    fpr = client.get_master_fingerprint()
    print(f"Fingerprint: {fpr.hex()}")

    if fpr.hex() != "f5acc2fd":
        print("This test assumes that the device is onboarded with the default mnemonic of Speculos")
        client.stop()
        exit(1)

    wallet = WalletPolicy(
        "",
        "tr(@0/**)",
        [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
        ],
    )
    psbt = PSBT()
    psbt.deserialize("cHNidP8BAJUCAAAAAqG4I9IzbWlLSTTvm25bfeF6BVE9qKKdsCouy8eppv5tAQAAAAD9////FveaMWPsN+g8VMbi6P9s2IOOg17zrcPf1ZYnyUnsJAkAAAAAAP3///8C8qapAAAAAAAiUSALjnSGvDBqCu+3p8AK8EBVQtsazXPuzKgnccz1/l62DwAAAAAAAAAABWoDRk9PAAAAAAABASunhqkAAAAAACJRINj08dGJltthuxyvVCPeJdih7unJUNN+b/oCMBLV5i4NIRYhLqKFalzxEOZqK+nXNTFHk/28s4iyuPE/K2remC569RkA9azC/VYAAIABAACAAAAAgAEAAAAAAAAAARcgIS6ihWpc8RDmaivp1zUxR5P9vLOIsrjxPytq3pguevUAAQErOTAAAAAAAAAiUSCHtA8hlu4BzfGu7dqCwmls1lYlShMPirSpdE1UaM3XBSEWh7QPIZbuAc3xru3agsJpbNZWJUoTD4q0qXRNVGjN1wURAPWswv1WAACAAQAAgGMAAIABFyCHtA8hlu4BzfGu7dqCwmls1lYlShMPirSpdE1UaM3XBQABBSACkIHs5WFqocuZMZ/Eh07+5H8IzrpfYARjbIxDQJpfCiEHApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwoZAPWswv1WAACAAQAAgAAAAIABAAAAAgAAAAAA")

    try:
        sign_results = client.sign_psbt(psbt, wallet, None)
    except Exception as e:
        print("Error signing PSBT:", e)
        client.stop()
        exit(1)

    print("Results of sign_psbt:", sign_results)

    assert len(sign_results) == 2

    signatures = list(sorted(sign_results))

    # Test that the signature is for the correct pubkey
    i_0, psig_0 = signatures[0]
    assert i_0 == 0
    # This is the key derived at m/86'/1'/0'/1/0, tweaked as per BIP-86
    assert psig_0.pubkey == bytes.fromhex(
        "d8f4f1d18996db61bb1caf5423de25d8a1eee9c950d37e6ffa023012d5e62e0d")

    i_1, psig_1 = signatures[1]
    assert i_1 == 1
    # This is the key derived at m/86'/1'/99'/1/0, and it is NOT tweaked
    assert psig_1.pubkey == bytes.fromhex(
        "87b40f2196ee01cdf1aeedda82c2696cd656254a130f8ab4a9744d5468cdd705")

    # Add partial signatures to the PSBT
    psbt.inputs[0].tap_key_sig = psig_0.signature
    psbt.inputs[1].tap_key_sig = psig_1.signature

    print("Signed PSBT:", psbt.serialize())

    client.stop()
