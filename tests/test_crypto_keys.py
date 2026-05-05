from btc import (
    Wallet,
    address_to_pubkey_hash,
    base58check_decode,
    base58check_encode,
    double_sha256,
    hash160,
    pubkey_to_address,
    verify_signature,
)


def test_double_sha256_known_vector():
    # double-SHA256("hello") matches the well-known value.
    assert double_sha256(b"hello").hex() == (
        "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
    )


def test_hash160_length():
    assert len(hash160(b"hello")) == 20


def test_base58check_round_trip():
    payload = b"\x6f" + b"\x11" * 20
    encoded = base58check_encode(payload)
    assert base58check_decode(encoded) == payload


def test_base58check_rejects_bad_checksum():
    payload = b"\x6f" + b"\x22" * 20
    s = base58check_encode(payload)
    # Flip a character in the middle — checksum should fail.
    bad = s[:5] + ("X" if s[5] != "X" else "Y") + s[6:]
    try:
        base58check_decode(bad)
    except ValueError:
        return
    raise AssertionError("expected bad checksum to raise")


def test_address_round_trip():
    w = Wallet.new()
    addr = w.address
    assert addr == pubkey_to_address(w.pubkey)
    assert address_to_pubkey_hash(addr) == w.pubkey_hash


def test_sign_and_verify():
    w = Wallet.new()
    msg = b"\x42" * 32
    sig = w.sign(msg)
    assert verify_signature(w.pubkey, msg, sig)
    # Wrong message
    assert not verify_signature(w.pubkey, b"\x43" * 32, sig)
    # Wrong key
    other = Wallet.new()
    assert not verify_signature(other.pubkey, msg, sig)


def test_sign_is_deterministic_rfc6979():
    w = Wallet.new()
    msg = b"\xab" * 32
    assert w.sign(msg) == w.sign(msg)


def test_pubkey_for_privkey_one_is_generator():
    """privkey d=1 must yield 1·G = G. Catches any bug in scalar_mul or
    compressed serialization, since G's coordinates are hardcoded constants."""
    from btc import Point

    assert (1 * Point.G).compress().hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )


def test_signature_pinned_known_answer():
    """Regression guard for deterministic signing: privkey=1, msg=32 zero bytes
    must always produce this exact DER signature. If this changes, something
    in RFC 6979, ECDSA, low-s normalization, or DER encoding has shifted."""
    priv = (1).to_bytes(32, "big")
    msg = b"\x00" * 32
    sig = Wallet(privkey=priv, pubkey=b"").sign(msg)
    assert sig.hex() == (
        "3045022100a0b37f8fba683cc68f6574cd43b39f0343a50008bf6ccea9d13231d9e7e2e1e4"
        "022011edc8d307254296264aebfc3dc76cd8b668373a072fd64665b50000e9fcce52"
    )
