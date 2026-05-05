from btc import (
    COINBASE_TXID,
    COINBASE_VOUT,
    Block,
    BlockHeader,
    Transaction,
    TxIn,
    TxOut,
    Wallet,
    double_sha256,
    header_meets_target,
    merkle_root,
    mine,
    p2pkh_script_pubkey,
)


def test_merkle_root_single_tx():
    h = double_sha256(b"hello")
    assert merkle_root([h]) == h


def test_merkle_root_pair():
    a, b = double_sha256(b"a"), double_sha256(b"b")
    assert merkle_root([a, b]) == double_sha256(a + b)


def test_merkle_root_odd_duplicates_last():
    """CVE-2012-2459: odd levels duplicate the last entry. Two distinct lists
    differing only by an appended duplicate produce the SAME root."""
    a, b, c = double_sha256(b"a"), double_sha256(b"b"), double_sha256(b"c")
    assert merkle_root([a, b, c]) == merkle_root([a, b, c, c])


def test_mine_finds_nonce_at_loose_target():
    w = Wallet.new()
    coinbase = Transaction(
        inputs=[TxIn(COINBASE_TXID, COINBASE_VOUT, b"\x00")],
        outputs=[TxOut(50, p2pkh_script_pubkey(w.pubkey_hash))],
    )
    bits = 0x1F00FFFF
    header = BlockHeader(1, b"\x00" * 32, merkle_root([coinbase.txid()]), 1700000000, bits, 0)
    block = Block(header=header, transactions=[coinbase])
    assert mine(block, max_nonce=10_000_000)
    assert header_meets_target(block.header)
