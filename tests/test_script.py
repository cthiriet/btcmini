from btc import (
    Wallet,
    evaluate,
    hash160,
    p2pkh_script_pubkey,
    p2pkh_script_sig,
    verify_signature,
)


def _checker_always_true():
    return lambda sig, pk: True


def _checker_always_false():
    return lambda sig, pk: False


def test_p2pkh_succeeds_with_correct_pubkey_and_valid_sig():
    w = Wallet.new()
    sig = b"DER-PLACEHOLDER"
    script = p2pkh_script_sig(sig, w.pubkey) + p2pkh_script_pubkey(w.pubkey_hash)
    assert evaluate(script, _checker_always_true()) is True


def test_p2pkh_fails_when_pubkey_hash_mismatches():
    w1, w2 = Wallet.new(), Wallet.new()
    sig = b"DER-PLACEHOLDER"
    # scriptSig presents w1's pubkey, but scriptPubKey commits to w2's hash.
    script = p2pkh_script_sig(sig, w1.pubkey) + p2pkh_script_pubkey(w2.pubkey_hash)
    assert evaluate(script, _checker_always_true()) is False


def test_p2pkh_fails_when_signature_invalid():
    w = Wallet.new()
    sig = b"DER-PLACEHOLDER"
    script = p2pkh_script_sig(sig, w.pubkey) + p2pkh_script_pubkey(w.pubkey_hash)
    assert evaluate(script, _checker_always_false()) is False


def test_p2pkh_with_real_signature():
    # End-to-end with a real signature over an arbitrary 32-byte digest.
    w = Wallet.new()
    digest = b"\x33" * 32
    sig = w.sign(digest)
    script = p2pkh_script_sig(sig, w.pubkey) + p2pkh_script_pubkey(w.pubkey_hash)

    def checker(s, pk):
        return verify_signature(pk, digest, s)

    assert evaluate(script, checker) is True


def test_p2pkh_pubkey_hash_must_be_20_bytes():
    try:
        p2pkh_script_pubkey(b"\x00" * 19)
    except ValueError:
        return
    raise AssertionError("expected ValueError for short pkh")


def test_pubkey_hash_matches_hash160_of_pubkey():
    w = Wallet.new()
    assert w.pubkey_hash == hash160(w.pubkey)
