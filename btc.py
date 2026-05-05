"""btcmini — a minimal Bitcoin in one file. For learning, not for value.

P2PKH only. No SegWit, no Taproot, no real network. The bits that carry
conceptual weight: secp256k1 ECDSA, Script VM, sighash, UTXO bookkeeping,
PoW, and reorgs. No third-party crypto — secp256k1 is built from scratch
on top of `int` and `pow(x, -1, p)`.

Sections:
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
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import base58

# ─────────────────────────────────────────────────────────────────────────────
# 1. Hashes & Base58Check
#
# Bitcoin uses double-SHA256 almost everywhere (txids, block hashes, sighash,
# merkle trees) and HASH160 = RIPEMD160(SHA256(x)) for pubkey-to-address.
# ─────────────────────────────────────────────────────────────────────────────


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", sha256(data)).digest()


def base58check_encode(payload: bytes) -> str:
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode("ascii")


def base58check_decode(s: str) -> bytes:
    raw = base58.b58decode(s)
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("base58check: bad checksum")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# 2. secp256k1 — the elliptic curve under every Bitcoin signature.
#
# The curve: y² = x³ + 7 over F_p, with prime p just under 2²⁵⁶. The "group
# order" n is the number of distinct points G can reach by repeated addition;
# a private key is just an integer in [1, n).
#
# !! NOT CONSTANT-TIME. _scalar_mul branches on secret bits via `if k & 1`,
# leaking the private key over a timing side-channel. Fine for a toy chain,
# disastrous for anything real. (The popular `ecdsa` PyPI lib has the same
# problem — constant-time secp256k1 in pure Python is genuinely hard.)
# ─────────────────────────────────────────────────────────────────────────────

# Curve parameters from https://www.secg.org/sec2-v2.pdf §2.4.1
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


class Point:
    """An affine point on secp256k1: y² = x³ + 7 (mod p).

    Represents the group identity (point at infinity) as `Point(None, None)`;
    use the `Point.INFINITY` singleton. Supports `P + Q` and `k * P` so the
    ECDSA code reads like the textbook (`R = u1*G + u2*pub`)."""

    __slots__ = ("x", "y")

    def __init__(self, x: int | None, y: int | None) -> None:
        self.x = x
        self.y = y

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Point) and self.x == other.x and self.y == other.y

    def __hash__(self) -> int:
        return hash((self.x, self.y))

    def __repr__(self) -> str:
        return "Point(∞)" if self.is_infinity else f"Point(x={self.x:#x}, y={self.y:#x})"

    def __add__(self, other: Point) -> Point:
        """Group law: slope m comes from the chord (P≠Q) or the tangent (P=Q),
        third intersection with the curve negated gives the result."""
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        p = SECP256K1_P
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return Point.INFINITY  # P + (-P) = ∞
            # P == Q (doubling). Slope = 3x²/(2y) since the curve has a=0.
            m = (3 * x1 * x1 * pow(2 * y1, -1, p)) % p
        else:
            m = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return Point(x3, y3)

    def __rmul__(self, k: int) -> Point:
        """k·P via double-and-add. NOT constant-time — branches on bits of k."""
        result = Point.INFINITY
        addend = self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def compress(self) -> bytes:
        """33-byte compressed encoding: 0x02/0x03 (y parity) || X (32 BE bytes)."""
        assert not self.is_infinity
        return (b"\x02" if self.y % 2 == 0 else b"\x03") + self.x.to_bytes(32, "big")

    @classmethod
    def decompress(cls, pub: bytes) -> Point:
        """Recover y from x using y² = x³ + 7. Pick the parity matching pub[0].
        Square root via y = (y²)^((p+1)/4) mod p, valid because p ≡ 3 (mod 4)."""
        p = SECP256K1_P
        x = int.from_bytes(pub[1:], "big")
        y = pow((pow(x, 3, p) + 7) % p, (p + 1) // 4, p)
        if (y & 1) != (pub[0] & 1):
            y = p - y
        return cls(x, y)


Point.INFINITY = Point(None, None)
Point.G = Point(SECP256K1_GX, SECP256K1_GY)


def _rfc6979_k(privkey: bytes, msg_hash: bytes) -> int:
    """Deterministic nonce per RFC 6979 §3.2 (HMAC-SHA256 instantiation).
    Without this, a buggy CSPRNG that repeats k across two signatures of
    different messages leaks the private key — this is how the PS3 was broken."""
    n = SECP256K1_N
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + privkey + msg_hash, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + privkey + msg_hash, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < n:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def _ecdsa_sign(privkey: bytes, msg_hash: bytes) -> tuple[int, int]:
    """Returns (r, s) with low-s normalization (BIP-62)."""
    n = SECP256K1_N
    d = int.from_bytes(privkey, "big")
    z = int.from_bytes(msg_hash, "big")
    while True:
        k = _rfc6979_k(privkey, msg_hash)
        R = k * Point.G
        r = R.x % n
        if r == 0:
            continue
        s = (pow(k, -1, n) * (z + r * d)) % n
        if s == 0:
            continue
        # BIP-62 low-s: bitcoin nodes reject sigs with s > n/2. Negating s
        # produces a second valid signature for the same message — fixing s
        # to the lower half kills that malleability.
        if s > n // 2:
            s = n - s
        return r, s


def _ecdsa_verify(pubkey_pt: Point, msg_hash: bytes, r: int, s: int) -> bool:
    n = SECP256K1_N
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int.from_bytes(msg_hash, "big")
    w = pow(s, -1, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    R = u1 * Point.G + u2 * pubkey_pt
    if R.is_infinity:
        return False
    return R.x % n == r


# DER: ECDSA signatures are SEQUENCE { INTEGER r, INTEGER s }, i.e.
# 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>. INTEGERs are big-endian
# minimal-length, prefixed with 0x00 if the high bit is set (so they aren't
# misread as negative two's-complement).


def _der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def _der_encode(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _der_decode(sig: bytes) -> tuple[int, int]:
    if sig[0] != 0x30:
        raise ValueError("DER: not a sequence")
    body = sig[2 : 2 + sig[1]]
    if body[0] != 0x02:
        raise ValueError("DER: r is not INTEGER")
    rlen = body[1]
    r = int.from_bytes(body[2 : 2 + rlen], "big")
    rest = body[2 + rlen :]
    if rest[0] != 0x02:
        raise ValueError("DER: s is not INTEGER")
    slen = rest[1]
    s = int.from_bytes(rest[2 : 2 + slen], "big")
    return r, s


# ─────────────────────────────────────────────────────────────────────────────
# 3. P2PKH addresses & wallet
#
# Pubkey is serialized compressed (33 bytes): 0x02/0x03 || X.
# Address = Base58Check(0x00 || HASH160(pubkey)) — starts with '1', mainnet
# format. The keypair is a real secp256k1 keypair; the chain it lives on is not.
# ─────────────────────────────────────────────────────────────────────────────

ADDRESS_VERSION = 0x00  # mainnet P2PKH


def pubkey_to_address(pubkey: bytes) -> str:
    return base58check_encode(bytes([ADDRESS_VERSION]) + hash160(pubkey))


def address_to_pubkey_hash(addr: str) -> bytes:
    payload = base58check_decode(addr)
    if payload[0] != ADDRESS_VERSION or len(payload) != 21:
        raise ValueError("address: wrong version or length")
    return payload[1:]


@dataclass
class Wallet:
    privkey: bytes  # 32 bytes
    pubkey: bytes  # 33 bytes, compressed

    @classmethod
    def new(cls) -> Wallet:
        # Reject the (vanishingly unlikely) zero / out-of-range draw.
        while True:
            d = int.from_bytes(os.urandom(32), "big")
            if 1 <= d < SECP256K1_N:
                break
        return cls(privkey=d.to_bytes(32, "big"), pubkey=(d * Point.G).compress())

    @property
    def pubkey_hash(self) -> bytes:
        return hash160(self.pubkey)

    @property
    def address(self) -> str:
        return pubkey_to_address(self.pubkey)

    def sign(self, msg32: bytes) -> bytes:
        """Sign a 32-byte digest; returns DER-encoded canonical (low-s) signature."""
        r, s = _ecdsa_sign(self.privkey, msg32)
        return _der_encode(r, s)


def verify_signature(pubkey: bytes, msg32: bytes, sig_der: bytes) -> bool:
    try:
        r, s = _der_decode(sig_der)
        return _ecdsa_verify(Point.decompress(pubkey), msg32, r, s)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 4. varint  (Bitcoin's compact length prefix)
# ─────────────────────────────────────────────────────────────────────────────


def encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Script VM — only enough opcodes to run P2PKH.
#
# A P2PKH spend evaluates: <sig> <pubkey> OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
# scriptSig and scriptPubKey are concatenated and run on a single stack.
#
# Encoding: each item is either an opcode byte or a data push. Pushes <0x4C
# bytes use the length byte directly as the opcode; we don't support
# OP_PUSHDATA{1,2,4} because pubkeys/sigs/hashes all fit under 75 bytes.
# ─────────────────────────────────────────────────────────────────────────────

OP_0 = 0x00
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC

Script = bytes
SigChecker = Callable[[bytes, bytes], bool]  # (sig+hashtype, pubkey) -> bool


def encode_script(items: list[int | bytes]) -> Script:
    out = bytearray()
    for item in items:
        if isinstance(item, int):
            out.append(item)
        elif item == b"":
            out.append(OP_0)
        elif len(item) < 0x4C:
            out.append(len(item))
            out.extend(item)
        else:
            raise ValueError(f"push too large: {len(item)} bytes")
    return bytes(out)


def _decode_script(script: Script) -> list[int | bytes]:
    out: list[int | bytes] = []
    i = 0
    while i < len(script):
        b = script[i]
        if 0x01 <= b < 0x4C:
            out.append(bytes(script[i + 1 : i + 1 + b]))
            i += 1 + b
        elif b == OP_0:
            out.append(b"")
            i += 1
        else:
            out.append(b)
            i += 1
    return out


def evaluate(script: Script, checker: SigChecker) -> bool:
    """Run scriptSig || scriptPubKey. Success = no error and top is truthy."""
    stack: list[bytes] = []
    for op in _decode_script(script):
        if isinstance(op, bytes):
            stack.append(op)
        elif op == OP_DUP:
            if not stack:
                return False
            stack.append(stack[-1])
        elif op == OP_HASH160:
            if not stack:
                return False
            stack.append(hash160(stack.pop()))
        elif op == OP_EQUALVERIFY:
            if len(stack) < 2 or stack.pop() != stack.pop():
                return False
        elif op == OP_CHECKSIG:
            if len(stack) < 2:
                return False
            pubkey = stack.pop()
            sig = stack.pop()
            stack.append(b"\x01" if checker(sig, pubkey) else b"")
        else:
            return False
    return bool(stack) and any(b for b in stack[-1])


def p2pkh_script_pubkey(pubkey_hash: bytes) -> Script:
    """OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG"""
    if len(pubkey_hash) != 20:
        raise ValueError("p2pkh: pkh must be 20 bytes")
    return encode_script([OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG])


def p2pkh_script_sig(sig_with_hashtype: bytes, pubkey: bytes) -> Script:
    """<sig+hashtype> <pubkey>"""
    return encode_script([sig_with_hashtype, pubkey])


# ─────────────────────────────────────────────────────────────────────────────
# 6. Transactions, sighash, signing.
#
# Sighash is the bug-magnet, so let's spell out the legacy SIGHASH_ALL recipe:
#
#     For input i, the message that gets signed is double_sha256 of:
#       1. A copy of the transaction with...
#       2. ...every input's scriptSig set to empty bytes...
#       3. ...except input i's scriptSig, which is replaced by the *previous
#          output's scriptPubKey* (the script we're trying to spend).
#       4. Then append the sighash type as 4 little-endian bytes (0x01000000).
#
# The signature pushed on the stack is `DER(sig) || hashtype_byte`. So at
# verify time we strip the last byte, recompute the digest with that hashtype,
# and verify DER(sig) over it with the pubkey.
# ─────────────────────────────────────────────────────────────────────────────

SIGHASH_ALL = 0x01

COINBASE_TXID = b"\x00" * 32
COINBASE_VOUT = 0xFFFFFFFF


@dataclass
class TxIn:
    prev_txid: bytes
    prev_vout: int
    script_sig: Script
    sequence: int = 0xFFFFFFFF

    def serialize(self) -> bytes:
        return (
            self.prev_txid
            + self.prev_vout.to_bytes(4, "little")
            + encode_varint(len(self.script_sig))
            + self.script_sig
            + self.sequence.to_bytes(4, "little")
        )


@dataclass
class TxOut:
    amount: int
    script_pubkey: Script

    def serialize(self) -> bytes:
        return (
            self.amount.to_bytes(8, "little")
            + encode_varint(len(self.script_pubkey))
            + self.script_pubkey
        )


@dataclass
class Transaction:
    version: int = 1
    inputs: list[TxIn] = field(default_factory=list)
    outputs: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    def serialize(self) -> bytes:
        out = bytearray(self.version.to_bytes(4, "little"))
        out += encode_varint(len(self.inputs))
        for ti in self.inputs:
            out += ti.serialize()
        out += encode_varint(len(self.outputs))
        for to_ in self.outputs:
            out += to_.serialize()
        out += self.locktime.to_bytes(4, "little")
        return bytes(out)

    def txid(self) -> bytes:
        """Natural byte order. Block explorers display the reverse."""
        return double_sha256(self.serialize())

    def is_coinbase(self) -> bool:
        return (
            len(self.inputs) == 1
            and self.inputs[0].prev_txid == COINBASE_TXID
            and self.inputs[0].prev_vout == COINBASE_VOUT
        )


def sighash_legacy(tx: Transaction, input_index: int, prev_script_pubkey: Script) -> bytes:
    """SIGHASH_ALL preimage: blank every scriptSig, then put prev_script_pubkey
    on input_index, append hashtype as 4 LE bytes, double-SHA256."""
    modified = Transaction(
        version=tx.version,
        inputs=[
            TxIn(
                ti.prev_txid,
                ti.prev_vout,
                prev_script_pubkey if i == input_index else b"",
                ti.sequence,
            )
            for i, ti in enumerate(tx.inputs)
        ],
        outputs=tx.outputs,
        locktime=tx.locktime,
    )
    return double_sha256(modified.serialize() + SIGHASH_ALL.to_bytes(4, "little"))


def sign_input_p2pkh(
    tx: Transaction, input_index: int, prev_script_pubkey: Script, wallet: Wallet
) -> None:
    """Sign one P2PKH input in place — sets its scriptSig to <sig+ht> <pubkey>."""
    digest = sighash_legacy(tx, input_index, prev_script_pubkey)
    sig_with_ht = wallet.sign(digest) + bytes([SIGHASH_ALL])
    tx.inputs[input_index].script_sig = p2pkh_script_sig(sig_with_ht, wallet.pubkey)


def verify_p2pkh_input(tx: Transaction, input_index: int, prev_script_pubkey: Script) -> bool:
    """Run scriptSig || scriptPubKey for one input. True iff valid."""

    def checker(sig_with_ht: bytes, pubkey: bytes) -> bool:
        if not sig_with_ht:
            return False
        digest = sighash_legacy(tx, input_index, prev_script_pubkey)
        return verify_signature(pubkey, digest, sig_with_ht[:-1])

    full = tx.inputs[input_index].script_sig + prev_script_pubkey
    return evaluate(full, checker)


# ─────────────────────────────────────────────────────────────────────────────
# 7. UTXO + coinbase maturity.
#
# UTXO set is just `dict[OutPoint, UTXO]`. Coinbase outputs aren't spendable
# for COINBASE_MATURITY (=100) blocks — protects against reorgs invalidating
# spends of newly-minted coins.
# ─────────────────────────────────────────────────────────────────────────────

COINBASE_MATURITY = 100

OutPoint = tuple[bytes, int]  # (txid, vout)


@dataclass(frozen=True)
class UTXO:
    amount: int
    script_pubkey: Script
    height: int
    is_coinbase: bool


def is_mature(utxo: UTXO, current_height: int, maturity: int = COINBASE_MATURITY) -> bool:
    return not utxo.is_coinbase or current_height - utxo.height >= maturity


# ─────────────────────────────────────────────────────────────────────────────
# 8. Blocks: header + tx list + merkle root.
#
# CVE-2012-2459 footnote — replicated for fidelity:
#     When a level of the merkle tree has an odd number of nodes, Bitcoin
#     duplicates the LAST one before pairing. Two distinct tx lists can
#     therefore share the same merkle root, which led to block-malleability
#     attacks. Modern Bitcoin still has this property; it's mitigated at the
#     consensus layer by enforcing tx-uniqueness rules.
# ─────────────────────────────────────────────────────────────────────────────


def merkle_root(txids: list[bytes]) -> bytes:
    if not txids:
        return b"\x00" * 32
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # CVE-2012-2459 quirk
        layer = [double_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


@dataclass
class BlockHeader:
    version: int
    prev_block_hash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int

    def serialize(self) -> bytes:
        return (
            self.version.to_bytes(4, "little")
            + self.prev_block_hash
            + self.merkle_root
            + self.timestamp.to_bytes(4, "little")
            + self.bits.to_bytes(4, "little")
            + self.nonce.to_bytes(4, "little")
        )

    def hash(self) -> bytes:
        return double_sha256(self.serialize())


@dataclass
class Block:
    header: BlockHeader
    transactions: list[Transaction] = field(default_factory=list)

    @property
    def txids(self) -> list[bytes]:
        return [t.txid() for t in self.transactions]

    def compute_merkle_root(self) -> bytes:
        return merkle_root(self.txids)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Proof-of-work.
#
# Bitcoin's `bits` is a 32-bit packed representation of a 256-bit target:
#     bits   = exp(1 byte) || mantissa(3 bytes)
#     target = mantissa << 8*(exp - 3)
#
# Block hash interpreted as a little-endian integer must be < target.
# ─────────────────────────────────────────────────────────────────────────────


def bits_to_target(bits: int) -> int:
    exp = bits >> 24
    mantissa = bits & 0x007FFFFF
    if exp <= 3:
        return mantissa >> (8 * (3 - exp))
    return mantissa << (8 * (exp - 3))


def header_meets_target(header: BlockHeader) -> bool:
    return int.from_bytes(header.hash(), "little") < bits_to_target(header.bits)


def cumulative_work(bits: int) -> int:
    """Approximate work for a block: 2²⁵⁶ / (target+1). Higher = harder."""
    return (1 << 256) // (bits_to_target(bits) + 1)


def mine(block: Block, max_nonce: int = 1 << 32) -> bool:
    """Brute-force the nonce until header < target. Mutates block.header.nonce."""
    target = bits_to_target(block.header.bits)
    for nonce in range(max_nonce):
        block.header.nonce = nonce
        if int.from_bytes(block.header.hash(), "little") < target:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 10. Blockchain — validation and reorgs (the densest section).
#
# The trick to reorgs: the *header tree* and the *active UTXO set* are
# different data structures with different update patterns.
#
#   - Header tree: append-only. Every block we accept stays here, parented by
#     its prev_hash. We track cumulative work per node.
#   - Active UTXO set: reflects exactly one chain (current tip → ... → genesis).
#     When a heavier chain appears, we walk the tip back to the common
#     ancestor (reverting each block) and then walk forward along the new chain.
#
# Per applied block we save *undo data* — the outputs we destroyed (so we can
# reincarnate them on revert) and the outpoints we created (so we know which
# to remove). Real Bitcoin stores this in `rev*.dat` files.
#
# If validation fails partway through a roll-forward, we restore the original
# tip — never get stuck in a half-applied state.
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ConsensusParams:
    bits: int = 0x1F00FFFF  # very loose fixed difficulty
    initial_subsidy: int = 50
    halving_interval: int = 210_000
    coinbase_maturity: int = COINBASE_MATURITY


def block_subsidy(height: int, params: ConsensusParams) -> int:
    return params.initial_subsidy >> (height // params.halving_interval)


@dataclass
class IndexEntry:
    block: Block
    height: int
    total_work: int
    prev_hash: bytes


@dataclass
class UndoData:
    spent: list[tuple[OutPoint, UTXO]] = field(default_factory=list)
    created: list[OutPoint] = field(default_factory=list)


class ValidationError(Exception):
    pass


class OrphanBlock(Exception):
    """Parent not yet known. Real Bitcoin would queue these; we just reject."""


def make_coinbase(address: str, amount: int, tag: bytes = b"") -> Transaction:
    """A coinbase has one synthetic input. The scriptSig is arbitrary; real
    Bitcoin uses it for the BIP34 height push and a miner tag. We length-prefix
    `tag` so different tags produce different txids."""
    sig = encode_varint(len(tag)) + tag
    return Transaction(
        version=1,
        inputs=[TxIn(COINBASE_TXID, COINBASE_VOUT, sig)],
        outputs=[TxOut(amount, p2pkh_script_pubkey(address_to_pubkey_hash(address)))],
    )


def assemble_block(
    prev_hash: bytes, txs: list[Transaction], bits: int, timestamp: int | None = None
) -> Block:
    """Build a candidate block (caller mines it). _apply_block re-validates."""
    return Block(
        header=BlockHeader(
            version=1,
            prev_block_hash=prev_hash,
            merkle_root=merkle_root([t.txid() for t in txs]),
            timestamp=timestamp if timestamp is not None else int(time.time()),
            bits=bits,
            nonce=0,
        ),
        transactions=txs,
    )


class Blockchain:
    def __init__(
        self,
        genesis_address: str,
        params: ConsensusParams | None = None,
        genesis_timestamp: int = 1_700_000_000,
    ) -> None:
        self.params = params or ConsensusParams()
        self.index: dict[bytes, IndexEntry] = {}
        self.undo: dict[bytes, UndoData] = {}
        self.utxo: dict[OutPoint, UTXO] = {}

        coinbase = make_coinbase(genesis_address, block_subsidy(0, self.params), tag=b"genesis")
        genesis = Block(
            header=BlockHeader(
                version=1,
                prev_block_hash=b"\x00" * 32,
                merkle_root=merkle_root([coinbase.txid()]),
                timestamp=genesis_timestamp,
                bits=self.params.bits,
                nonce=0,
            ),
            transactions=[coinbase],
        )
        if not mine(genesis):
            raise RuntimeError("could not mine genesis")
        gh = genesis.header.hash()
        self.index[gh] = IndexEntry(genesis, 0, cumulative_work(genesis.header.bits), b"\x00" * 32)
        self.tip = gh
        self.genesis_hash = gh
        self._apply_block(genesis, height=0)

    @property
    def height(self) -> int:
        return self.index[self.tip].height

    def accept_block(self, block: Block) -> None:
        """Add a block to the index. Switch tips if it makes a heavier chain."""
        bh = block.header.hash()
        if bh in self.index:
            return
        ph = block.header.prev_block_hash
        if ph not in self.index:
            raise OrphanBlock(f"unknown parent {ph.hex()[:8]}")
        if not header_meets_target(block.header):
            raise ValidationError("PoW: header does not meet target")
        if block.header.bits != self.params.bits:
            raise ValidationError("PoW: unexpected bits")
        if block.header.merkle_root != merkle_root(block.txids):
            raise ValidationError("merkle root mismatch")
        if not block.transactions or not block.transactions[0].is_coinbase():
            raise ValidationError("first tx must be coinbase")
        if any(t.is_coinbase() for t in block.transactions[1:]):
            raise ValidationError("only first tx may be coinbase")

        parent = self.index[ph]
        new_work = parent.total_work + cumulative_work(block.header.bits)
        self.index[bh] = IndexEntry(block, parent.height + 1, new_work, ph)

        if new_work > self.index[self.tip].total_work:
            self._maybe_reorg(bh)

    def _maybe_reorg(self, new_tip: bytes) -> None:
        """Switch the active chain to end at new_tip. Restore on failure."""
        old_tip = self.tip
        common = self._common_ancestor(old_tip, new_tip)
        path_back = self._path_to(common, old_tip)
        path_fwd = self._path_to(common, new_tip)

        utxo_backup = self.utxo.copy()
        undo_backup = dict(self.undo)
        try:
            for h in reversed(path_back):
                self._revert_block(self.index[h].block)
            self.tip = common
            for h in path_fwd:
                self._apply_block(self.index[h].block, height=self.index[h].height)
                self.tip = h
        except Exception:
            self.utxo = utxo_backup
            self.undo = undo_backup
            self.tip = old_tip
            raise

    def _common_ancestor(self, a: bytes, b: bytes) -> bytes:
        ha, hb = self.index[a].height, self.index[b].height
        while ha > hb:
            a = self.index[a].prev_hash
            ha -= 1
        while hb > ha:
            b = self.index[b].prev_hash
            hb -= 1
        while a != b:
            a = self.index[a].prev_hash
            b = self.index[b].prev_hash
        return a

    def _path_to(self, ancestor: bytes, descendant: bytes) -> list[bytes]:
        """Hashes from ancestor (exclusive) to descendant (inclusive), oldest first."""
        path = []
        h = descendant
        while h != ancestor:
            path.append(h)
            h = self.index[h].prev_hash
        path.reverse()
        return path

    def _apply_block(self, block: Block, height: int) -> None:
        """Validate fully and update the UTXO set. Records undo data."""
        undo = UndoData()
        total_fees = 0
        spent_in_block: set = set()

        for tx in block.transactions:
            txid = tx.txid()

            if tx.is_coinbase():
                # Coinbase amount is checked at the end (needs total fees).
                for vout, txo in enumerate(tx.outputs):
                    op = (txid, vout)
                    self.utxo[op] = UTXO(txo.amount, txo.script_pubkey, height, True)
                    undo.created.append(op)
                continue

            in_total = 0
            for in_idx, ti in enumerate(tx.inputs):
                op = (ti.prev_txid, ti.prev_vout)
                if op in spent_in_block:
                    raise ValidationError(f"intra-block double spend: {op[0].hex()[:8]}:{op[1]}")
                if op not in self.utxo:
                    raise ValidationError(f"missing UTXO: {op[0].hex()[:8]}:{op[1]}")
                prev = self.utxo[op]
                if not is_mature(prev, height, self.params.coinbase_maturity):
                    raise ValidationError(f"coinbase not mature: {op[0].hex()[:8]}:{op[1]}")
                if not verify_p2pkh_input(tx, in_idx, prev.script_pubkey):
                    raise ValidationError(f"script verification failed input {in_idx}")
                in_total += prev.amount
                spent_in_block.add(op)
                undo.spent.append((op, prev))
                del self.utxo[op]

            out_total = sum(o.amount for o in tx.outputs)
            if out_total > in_total:
                raise ValidationError("outputs exceed inputs")
            total_fees += in_total - out_total

            for vout, txo in enumerate(tx.outputs):
                op = (txid, vout)
                self.utxo[op] = UTXO(txo.amount, txo.script_pubkey, height, False)
                undo.created.append(op)

        coinbase_out = sum(o.amount for o in block.transactions[0].outputs)
        max_coinbase = block_subsidy(height, self.params) + total_fees
        if coinbase_out > max_coinbase:
            raise ValidationError(f"coinbase pays too much: {coinbase_out} > {max_coinbase}")

        self.undo[block.header.hash()] = undo

    def _revert_block(self, block: Block) -> None:
        """Undo what _apply_block did. Trusts the saved undo data."""
        undo = self.undo.pop(block.header.hash())
        for op in undo.created:
            self.utxo.pop(op, None)
        for op, prev in undo.spent:
            self.utxo[op] = prev


# ─────────────────────────────────────────────────────────────────────────────
# 11. Mempool — pending tx pool with fee-rate selection.
#
# No replace-by-fee, no descendant packages, no eviction. Just enough to demo
# tx → mempool → block → confirmed.
# ─────────────────────────────────────────────────────────────────────────────


class Mempool:
    def __init__(self, chain: Blockchain) -> None:
        self.chain = chain
        self._entries: dict[bytes, tuple[Transaction, float]] = {}  # txid -> (tx, feerate)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def add(self, tx: Transaction) -> bytes:
        """Validate against the chain's UTXO set and add. Returns txid."""
        if tx.is_coinbase():
            raise ValueError("mempool: coinbases cannot be relayed")
        txid = tx.txid()
        if txid in self._entries:
            return txid

        in_total = 0
        spent: set = set()
        for in_idx, ti in enumerate(tx.inputs):
            op = (ti.prev_txid, ti.prev_vout)
            if op in spent:
                raise ValueError("mempool: tx spends same outpoint twice")
            if op not in self.chain.utxo:
                raise ValueError(f"mempool: missing UTXO {op[0].hex()[:8]}:{op[1]}")
            prev = self.chain.utxo[op]
            # Maturity check assumes this tx will land in the *next* block.
            if not is_mature(prev, self.chain.height + 1, self.chain.params.coinbase_maturity):
                raise ValueError("mempool: would spend immature coinbase")
            if not verify_p2pkh_input(tx, in_idx, prev.script_pubkey):
                raise ValueError(f"mempool: script verification failed input {in_idx}")
            in_total += prev.amount
            spent.add(op)

        out_total = sum(o.amount for o in tx.outputs)
        if out_total > in_total:
            raise ValueError("mempool: outputs exceed inputs")
        fee = in_total - out_total
        feerate = fee / max(1, len(tx.serialize()))
        self._entries[txid] = (tx, feerate)
        return txid

    def remove(self, txid: bytes) -> None:
        self._entries.pop(txid, None)

    def select_for_block(self, max_count: int | None = None) -> list[Transaction]:
        """Highest-feerate first, skipping conflicting/stale txs."""
        ordered = sorted(self._entries.values(), key=lambda e: -e[1])
        selected: list[Transaction] = []
        spent: set = set()
        for tx, _ in ordered:
            if max_count is not None and len(selected) >= max_count:
                break
            ops = [(ti.prev_txid, ti.prev_vout) for ti in tx.inputs]
            if any(op in spent or op not in self.chain.utxo for op in ops):
                continue
            selected.append(tx)
            spent.update(ops)
        return selected

    def reconcile(self) -> None:
        """Drop entries whose inputs no longer exist (after a block or reorg)."""
        stale = [
            txid
            for txid, (tx, _) in self._entries.items()
            if any((ti.prev_txid, ti.prev_vout) not in self.chain.utxo for ti in tx.inputs)
        ]
        for txid in stale:
            del self._entries[txid]

