from ledger_bitcoin import Chain, TransportClient, WalletPolicy
from ledger_bitcoin.client import NewClient as AppClient

CLA_APP = 0xE1
INS_CUSTOM_XOR = 128

if __name__ == '__main__':
    transport = TransportClient()
    client = AppClient(transport, chain=Chain.TEST)

    # Tests a custom APDU. A real application should implement a
    # custom client instad of using raw APDUs.
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
    psbt = "cHNidP8BAJUCAAAAAqG4I9IzbWlLSTTvm25bfeF6BVE9qKKdsCouy8eppv5tAQAAAAD9////FveaMWPsN+g8VMbi6P9s2IOOg17zrcPf1ZYnyUnsJAkAAAAAAP3///8C8qapAAAAAAAiUSALjnSGvDBqCu+3p8AK8EBVQtsazXPuzKgnccz1/l62DwAAAAAAAAAABWoDRk9PAAAAAAABASunhqkAAAAAACJRINj08dGJltthuxyvVCPeJdih7unJUNN+b/oCMBLV5i4NIRYhLqKFalzxEOZqK+nXNTFHk/28s4iyuPE/K2remC569RkA9azC/VYAAIABAACAAAAAgAEAAAAAAAAAARcgIS6ihWpc8RDmaivp1zUxR5P9vLOIsrjxPytq3pguevUAAQErOTAAAAAAAAAiUSCHtA8hlu4BzfGu7dqCwmls1lYlShMPirSpdE1UaM3XBSEWh7QPIZbuAc3xru3agsJpbNZWJUoTD4q0qXRNVGjN1wURAPWswv1WAACAAQAAgGMAAIABFyCHtA8hlu4BzfGu7dqCwmls1lYlShMPirSpdE1UaM3XBQABBSACkIHs5WFqocuZMZ/Eh07+5H8IzrpfYARjbIxDQJpfCiEHApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwoZAPWswv1WAACAAQAAgAAAAIABAAAAAgAAAAAA"

    try:
        sign_results = client.sign_psbt(psbt, wallet, None)
    except Exception as e:
        print("Error signing PSBT:", e)
        client.stop()
        exit(1)

    print("Results of sign_psbt:", sign_results)

    client.stop()
