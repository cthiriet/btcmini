"""Chain-level tests: block acceptance, validation, reorgs."""

import pytest

from btc import (
    Blockchain,
    ConsensusParams,
    OrphanBlock,
    Transaction,
    TxIn,
    TxOut,
    ValidationError,
    Wallet,
    assemble_block,
    block_subsidy,
    is_mature,
    make_coinbase,
    mine,
    p2pkh_script_pubkey,
    sign_input_p2pkh,
)

# Tiny coinbase maturity so we can spend coinbases quickly in tests.
SHORT_MATURITY = 2


def _params():
    return ConsensusParams(coinbase_maturity=SHORT_MATURITY)


def _mine_next(chain: Blockchain, miner: Wallet, extra_txs=None, tag: bytes = b""):
    """Build & mine a block on top of `chain.tip` paying the miner."""
    extra_txs = extra_txs or []
    fees = sum(
        sum(chain.utxo[(ti.prev_txid, ti.prev_vout)].amount for ti in t.inputs)
        - sum(o.amount for o in t.outputs)
        for t in extra_txs
    )
    height = chain.height + 1
    coinbase = make_coinbase(
        miner.address,
        block_subsidy(height, chain.params) + fees,
        tag=b"m" + tag + height.to_bytes(4, "big"),
    )
    block = assemble_block(
        chain.tip,
        [coinbase] + list(extra_txs),
        bits=chain.params.bits,
        timestamp=1_700_000_000 + height,
    )
    assert mine(block, max_nonce=10_000_000)
    return block


def _mature_alice_op(chain: Blockchain, alice: Wallet):
    spk = p2pkh_script_pubkey(alice.pubkey_hash)
    for op, u in chain.utxo.items():
        if u.script_pubkey == spk and is_mature(u, chain.height, chain.params.coinbase_maturity):
            return op, u
    raise AssertionError("alice has no mature output")


def test_genesis_paid_address_has_utxo():
    miner = Wallet.new()
    chain = Blockchain(genesis_address=miner.address, params=_params())
    assert chain.height == 0
    assert sum(u.amount for u in chain.utxo.values()) == 50  # initial subsidy


def test_mine_and_extend():
    miner = Wallet.new()
    chain = Blockchain(genesis_address=miner.address, params=_params())
    chain.accept_block(_mine_next(chain, miner))
    chain.accept_block(_mine_next(chain, miner))
    assert chain.height == 2


def test_orphan_rejected():
    miner = Wallet.new()
    chain = Blockchain(genesis_address=miner.address, params=_params())
    b1 = _mine_next(chain, miner)
    # Don't accept b1; build a child of it and submit that.
    coinbase = make_coinbase(miner.address, block_subsidy(2, chain.params), tag=b"orphan")
    block = assemble_block(
        b1.header.hash(), [coinbase], bits=chain.params.bits, timestamp=1_700_000_002
    )
    assert mine(block, max_nonce=10_000_000)
    with pytest.raises(OrphanBlock):
        chain.accept_block(block)


def test_send_funds_between_wallets():
    """End-to-end: mine some coinbases, then craft and confirm a P2PKH tx."""
    alice, bob = Wallet.new(), Wallet.new()
    chain = Blockchain(genesis_address=alice.address, params=_params())
    for _ in range(SHORT_MATURITY):
        chain.accept_block(_mine_next(chain, alice))

    op, u = _mature_alice_op(chain, alice)
    fee, send_amount = 1, u.amount - 6
    change = u.amount - fee - send_amount

    pay = Transaction(
        inputs=[TxIn(op[0], op[1], b"")],
        outputs=[
            TxOut(send_amount, p2pkh_script_pubkey(bob.pubkey_hash)),
            TxOut(change, p2pkh_script_pubkey(alice.pubkey_hash)),
        ],
    )
    sign_input_p2pkh(pay, 0, u.script_pubkey, alice)
    chain.accept_block(_mine_next(chain, alice, extra_txs=[pay]))

    bob_spk = p2pkh_script_pubkey(bob.pubkey_hash)
    assert any(u.amount == send_amount for u in chain.utxo.values() if u.script_pubkey == bob_spk)


def test_double_spend_within_block_rejected():
    alice, bob = Wallet.new(), Wallet.new()
    chain = Blockchain(genesis_address=alice.address, params=_params())
    for _ in range(SHORT_MATURITY):
        chain.accept_block(_mine_next(chain, alice))

    op, u = _mature_alice_op(chain, alice)

    def make_tx(receiver):
        tx = Transaction(
            inputs=[TxIn(op[0], op[1], b"")],
            outputs=[TxOut(u.amount - 1, p2pkh_script_pubkey(receiver.pubkey_hash))],
        )
        sign_input_p2pkh(tx, 0, u.script_pubkey, alice)
        return tx

    block = _mine_next(chain, alice, extra_txs=[make_tx(bob), make_tx(Wallet.new())])
    with pytest.raises(ValidationError, match="double spend"):
        chain.accept_block(block)


def test_coinbase_immaturity_rejected():
    alice = Wallet.new()
    chain = Blockchain(genesis_address=alice.address, params=ConsensusParams(coinbase_maturity=5))
    b1 = _mine_next(chain, alice)
    chain.accept_block(b1)
    # Try to spend b1's coinbase immediately (height 1, current 1).
    op = (b1.transactions[0].txid(), 0)
    u = chain.utxo[op]
    pay = Transaction(
        inputs=[TxIn(op[0], op[1], b"")],
        outputs=[TxOut(u.amount - 1, u.script_pubkey)],
    )
    sign_input_p2pkh(pay, 0, u.script_pubkey, alice)
    with pytest.raises(ValidationError, match="coinbase not mature"):
        chain.accept_block(_mine_next(chain, alice, extra_txs=[pay]))


def test_overpaid_coinbase_rejected():
    alice = Wallet.new()
    chain = Blockchain(genesis_address=alice.address, params=_params())
    bad = make_coinbase(alice.address, block_subsidy(1, chain.params) + 1, tag=b"greedy")
    block = assemble_block(chain.tip, [bad], bits=chain.params.bits, timestamp=1_700_000_001)
    assert mine(block, max_nonce=10_000_000)
    with pytest.raises(ValidationError, match="coinbase pays too much"):
        chain.accept_block(block)


def test_reorg_to_heavier_chain():
    """Build branch A (2 blocks), then branch B (3 blocks), assert reorg."""
    alice, bob = Wallet.new(), Wallet.new()
    chain = Blockchain(genesis_address=alice.address, params=_params())

    a1 = _mine_next(chain, alice, tag=b"A")
    chain.accept_block(a1)
    a2 = _mine_next(chain, alice, tag=b"A")
    chain.accept_block(a2)
    a1_cb = (a1.transactions[0].txid(), 0)
    a2_cb = (a2.transactions[0].txid(), 0)
    assert a1_cb in chain.utxo and a2_cb in chain.utxo

    def mine_on(parent, miner, height, tag):
        cb = make_coinbase(miner.address, block_subsidy(height, chain.params), tag=tag)
        block = assemble_block(
            parent, [cb], bits=chain.params.bits, timestamp=1_700_000_000 + height + 100
        )
        assert mine(block)
        return block

    g = chain.genesis_hash
    b1 = mine_on(g, bob, 1, b"B1")
    chain.accept_block(b1)
    assert chain.tip == a2.header.hash(), "B1 alone shouldn't trigger reorg"

    b2 = mine_on(b1.header.hash(), bob, 2, b"B2")
    chain.accept_block(b2)
    assert chain.tip == a2.header.hash(), "tied work shouldn't trigger reorg"

    b3 = mine_on(b2.header.hash(), bob, 3, b"B3")
    chain.accept_block(b3)

    assert chain.tip == b3.header.hash() and chain.height == 3
    assert a1_cb not in chain.utxo and a2_cb not in chain.utxo
    for blk in (b1, b2, b3):
        assert (blk.transactions[0].txid(), 0) in chain.utxo


def test_reorg_failure_restores_state():
    """If a roll-forward block is invalid, the original tip is restored."""
    alice = Wallet.new()
    chain = Blockchain(genesis_address=alice.address, params=_params())
    chain.accept_block(_mine_next(chain, alice, tag=b"A"))
    original_tip = chain.tip
    original_utxo_size = len(chain.utxo)

    bob = Wallet.new()
    g = chain.genesis_hash

    def mine_on(parent, height, tag, amount):
        cb = make_coinbase(bob.address, amount, tag=tag)
        block = assemble_block(
            parent, [cb], bits=chain.params.bits, timestamp=1_700_000_000 + height + 200
        )
        assert mine(block)
        return block

    b1 = mine_on(g, 1, b"B1ok", block_subsidy(1, chain.params))
    b2 = mine_on(b1.header.hash(), 2, b"B2bad", 999)

    chain.accept_block(b1)
    with pytest.raises(ValidationError):
        chain.accept_block(b2)

    assert chain.tip == original_tip
    assert len(chain.utxo) == original_utxo_size
