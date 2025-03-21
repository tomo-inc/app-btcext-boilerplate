

## The Foo app

This repository implements a protocol for clear signing transactions of a specific format that the bitcoin app does not support.

The Foo protocol expect transactions that are just like nmormal transactions (inputs and change outputs from a standard account compliant to BIP-44, BIP-49, BIP-84 or BIP-86), plus in additionn:
- a special 'magic input' that is a P2TR UTXO with taproot public key at a the fixed derivation path `m/86'/1'/99'`.
- an `OP_RETURN` output with the message `FOO`.

The app's UX validates that the transaction satisfies this protocol, and shows all the transaction details in the UX.

## Compiling the app

Initialize the submodule with

```
$ git submodule update --init --recursive
```

Compile the app [as usual](https://github.com/LedgerHQ/app-boilerplate#quick-start-guide).
You should be able to launch it using speculos.

## Running the tests

Create a Python virtual environment and install the requirements:

```
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r tests/requirements.txt
```

Launch the test suite; for example, if you compiled the app for Ledger Flex:

```
$ pytest --device=flex
```
