# btcmini

A minimal Bitcoin implementation for learning, in **one file**: [btc.py](btc.py).
Legacy P2PKH only — no SegWit, no Taproot, no real network layer. ~1000 lines
covering the parts that carry the conceptual weight: secp256k1 ECDSA from
scratch, Script VM, sighash, UTXO bookkeeping, PoW, reorgs, and a mempool.

Companion notebooks walk through the ideas interactively:

- [01_crypto.ipynb](01_crypto.ipynb) — hashes, secp256k1 group law, ECDSA, nonce-reuse and low-s malleability
- [02_script_and_tx.ipynb](02_script_and_tx.ipynb) — varint, Script VM, hand-built transaction, sighash, DER malleability

More notebooks will follow, covering the remaining sections of [btc.py](btc.py).

## Setup

```sh
uv sync
```

## Run

```sh
uv run pytest          # tests
```

## Lint & format

```sh
uv run ruff check .          # lint
uv run ruff check --fix .    # auto-fix
uv run ruff format .         # format
```

## Layout

Everything lives in [btc.py](btc.py), in numbered sections:

1. Hashes & Base58Check
2. secp256k1 (curve math, ECDSA, RFC 6979, DER)
3. P2PKH addresses & wallet
4. varint
5. Script VM (4 opcodes — enough for P2PKH)
6. Transactions, sighash, signing
7. UTXO + coinbase maturity
8. Block + merkle root (with the CVE-2012-2459 quirk)
9. Proof-of-work (compact-target encoding)
10. Blockchain validation + reorgs (with undo data)
11. Mempool
