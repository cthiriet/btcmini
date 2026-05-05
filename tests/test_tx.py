from btc import (
    Transaction,
    TxIn,
    TxOut,
    Wallet,
    p2pkh_script_pubkey,
    sighash_legacy,
    sign_input_p2pkh,
    verify_p2pkh_input,
)


def _funded_prev(wallet: Wallet, amount: int = 100):
    """Pretend a previous transaction paid `wallet` with `amount` at vout 0."""
    prev_pk = p2pkh_script_pubkey(wallet.pubkey_hash)
    prev = Transaction(
        inputs=[TxIn(b"\xaa" * 32, 0, b"")],
        outputs=[TxOut(amount, prev_pk)],
    )
    return prev, prev_pk


def test_sign_and_verify_p2pkh():
    sender, receiver = Wallet.new(), Wallet.new()
    prev, prev_pk = _funded_prev(sender, amount=1000)
    tx = Transaction(
        inputs=[TxIn(prev.txid(), 0, b"")],
        outputs=[TxOut(900, p2pkh_script_pubkey(receiver.pubkey_hash))],
    )
    sign_input_p2pkh(tx, 0, prev_pk, sender)
    assert verify_p2pkh_input(tx, 0, prev_pk) is True


def test_sighash_changes_when_outputs_change():
    """SIGHASH_ALL covers outputs — a sig on tx-A must NOT verify after the
    outputs change. This catches the classic 'steal the recipient' attack."""
    sender, receiver = Wallet.new(), Wallet.new()
    prev, prev_pk = _funded_prev(sender, amount=1000)
    tx = Transaction(
        inputs=[TxIn(prev.txid(), 0, b"")],
        outputs=[TxOut(900, p2pkh_script_pubkey(receiver.pubkey_hash))],
    )
    sign_input_p2pkh(tx, 0, prev_pk, sender)
    good_sig = tx.inputs[0].script_sig
    assert verify_p2pkh_input(tx, 0, prev_pk)

    attacker = Wallet.new()
    tx.outputs[0] = TxOut(900, p2pkh_script_pubkey(attacker.pubkey_hash))
    tx.inputs[0].script_sig = good_sig
    assert verify_p2pkh_input(tx, 0, prev_pk) is False


def test_sighash_does_not_include_other_inputs_scriptsigs():
    """SIGHASH_ALL blanks other inputs' scriptSigs. So signing input 1 must
    not invalidate the existing signature on input 0."""
    a, b = Wallet.new(), Wallet.new()
    prev_a, pk_a = _funded_prev(a, amount=500)
    prev_b, pk_b = _funded_prev(b, amount=500)
    tx = Transaction(
        inputs=[
            TxIn(prev_a.txid(), 0, b""),
            TxIn(prev_b.txid(), 0, b""),
        ],
        outputs=[TxOut(900, pk_a)],
    )
    digest_before = sighash_legacy(tx, 0, pk_a)
    sign_input_p2pkh(tx, 0, pk_a, a)
    digest_after = sighash_legacy(tx, 0, pk_a)
    assert digest_before == digest_after
    sign_input_p2pkh(tx, 1, pk_b, b)
    assert verify_p2pkh_input(tx, 0, pk_a)
    assert verify_p2pkh_input(tx, 1, pk_b)


def test_wrong_signer_fails():
    sender, impostor = Wallet.new(), Wallet.new()
    prev, prev_pk = _funded_prev(sender, amount=1000)
    tx = Transaction(
        inputs=[TxIn(prev.txid(), 0, b"")],
        outputs=[TxOut(900, prev_pk)],
    )
    sign_input_p2pkh(tx, 0, prev_pk, impostor)
    assert verify_p2pkh_input(tx, 0, prev_pk) is False
