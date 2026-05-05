import pytest

from btc import (
    Blockchain,
    ConsensusParams,
    Mempool,
    Transaction,
    TxIn,
    TxOut,
    Wallet,
    is_mature,
    p2pkh_script_pubkey,
    sign_input_p2pkh,
)
from tests.test_chain import _mine_next  # reuse helper

SHORT_MATURITY = 2


def _new_chain(alice):
    chain = Blockchain(
        genesis_address=alice.address, params=ConsensusParams(coinbase_maturity=SHORT_MATURITY)
    )
    for _ in range(SHORT_MATURITY):
        chain.accept_block(_mine_next(chain, alice))
    return chain


def _mature_utxo_for(chain, wallet):
    spk = p2pkh_script_pubkey(wallet.pubkey_hash)
    for op, u in chain.utxo.items():
        if u.script_pubkey == spk and is_mature(u, chain.height, chain.params.coinbase_maturity):
            return op, u
    raise AssertionError("no mature utxo")


def _pay_tx(sender, op, u, receiver, amount, fee):
    tx = Transaction(
        inputs=[TxIn(op[0], op[1], b"")],
        outputs=[
            TxOut(amount, p2pkh_script_pubkey(receiver.pubkey_hash)),
            TxOut(u.amount - amount - fee, p2pkh_script_pubkey(sender.pubkey_hash)),
        ],
    )
    sign_input_p2pkh(tx, 0, u.script_pubkey, sender)
    return tx


def test_add_valid_tx():
    alice, bob = Wallet.new(), Wallet.new()
    chain = _new_chain(alice)
    mp = Mempool(chain)
    op, u = _mature_utxo_for(chain, alice)
    txid = mp.add(_pay_tx(alice, op, u, bob, amount=u.amount - 5, fee=2))
    assert txid in mp


def test_reject_double_spend_within_tx():
    alice = Wallet.new()
    chain = _new_chain(alice)
    mp = Mempool(chain)
    op, u = _mature_utxo_for(chain, alice)
    tx = Transaction(
        inputs=[TxIn(op[0], op[1], b""), TxIn(op[0], op[1], b"")],
        outputs=[TxOut(u.amount * 2 - 1, p2pkh_script_pubkey(alice.pubkey_hash))],
    )
    sign_input_p2pkh(tx, 0, u.script_pubkey, alice)
    sign_input_p2pkh(tx, 1, u.script_pubkey, alice)
    with pytest.raises(ValueError, match="same outpoint"):
        mp.add(tx)


def test_reject_overspend():
    alice, bob = Wallet.new(), Wallet.new()
    chain = _new_chain(alice)
    mp = Mempool(chain)
    op, u = _mature_utxo_for(chain, alice)
    tx = Transaction(
        inputs=[TxIn(op[0], op[1], b"")],
        outputs=[TxOut(u.amount + 1, p2pkh_script_pubkey(bob.pubkey_hash))],
    )
    sign_input_p2pkh(tx, 0, u.script_pubkey, alice)
    with pytest.raises(ValueError, match="exceed inputs"):
        mp.add(tx)


def test_select_orders_by_feerate_and_avoids_conflicts():
    alice, bob = Wallet.new(), Wallet.new()
    chain = _new_chain(alice)
    mp = Mempool(chain)
    chain.accept_block(_mine_next(chain, alice))

    spk_alice = p2pkh_script_pubkey(alice.pubkey_hash)
    matures = [
        (op, u)
        for op, u in chain.utxo.items()
        if u.script_pubkey == spk_alice
        and is_mature(u, chain.height, chain.params.coinbase_maturity)
    ]
    assert len(matures) >= 2
    (op1, u1), (op2, u2) = matures[0], matures[1]

    tx_high = _pay_tx(alice, op1, u1, bob, amount=10, fee=20)
    tx_low_conflict = _pay_tx(alice, op1, u1, bob, amount=15, fee=5)
    tx_distinct = _pay_tx(alice, op2, u2, bob, amount=10, fee=8)
    mp.add(tx_high)
    mp.add(tx_low_conflict)
    mp.add(tx_distinct)

    txids = {t.txid() for t in mp.select_for_block()}
    assert tx_high.txid() in txids
    assert tx_distinct.txid() in txids
    assert tx_low_conflict.txid() not in txids


def test_reconcile_drops_stale():
    alice, bob = Wallet.new(), Wallet.new()
    chain = _new_chain(alice)
    mp = Mempool(chain)
    op, u = _mature_utxo_for(chain, alice)
    tx = _pay_tx(alice, op, u, bob, amount=u.amount - 5, fee=2)
    mp.add(tx)
    chain.accept_block(_mine_next(chain, alice, extra_txs=[tx]))
    mp.reconcile()
    assert tx.txid() not in mp
