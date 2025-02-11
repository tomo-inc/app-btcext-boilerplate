Initialize the submodule with

```
$ git submodule update --init --recursive
```


## Running the test

Install `ledger_bitcoin` in a virtual environment:

```
$ python -m venv venv
$ source venv/bin/activate
$ pip install ledger_bitcoin
```

The run the test with speculos:

```
python test.py
```
