from btc import UTXO, is_mature


def _u(coinbase=False, height=10):
    return UTXO(amount=10, script_pubkey=b"", height=height, is_coinbase=coinbase)


def test_coinbase_maturity():
    u = _u(coinbase=True, height=10)
    assert not is_mature(u, current_height=10, maturity=100)
    assert not is_mature(u, current_height=109, maturity=100)
    assert is_mature(u, current_height=110, maturity=100)


def test_non_coinbase_is_always_mature():
    assert is_mature(_u(coinbase=False, height=10), current_height=10)
