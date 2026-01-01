"""
Test that validates our fidelity bond proofs are compatible with the reference implementation.

This test will run in the e2e environment where both implementations are available.
"""

import struct
import base64
import hashlib
from coincurve import PrivateKey
import pytest


pytestmark = pytest.mark.reference


def _bitcoin_message_hash(message: bytes) -> bytes:
    """Hash a message using Bitcoin's message signing format."""
    prefix = b"\x18Bitcoin Signed Message:\n"
    msg_len = len(message)
    if msg_len < 253:
        varint = bytes([msg_len])
    elif msg_len < 0x10000:
        varint = b"\xfd" + msg_len.to_bytes(2, "little")
    elif msg_len < 0x100000000:
        varint = b"\xfe" + msg_len.to_bytes(4, "little")
    else:
        varint = b"\xff" + msg_len.to_bytes(8, "little")

    full_msg = prefix + varint + message
    return hashlib.sha256(hashlib.sha256(full_msg).digest()).digest()


def _sign_message_bitcoin(private_key: PrivateKey, message: bytes) -> bytes:
    """Sign a message using Bitcoin message signing format."""
    msg_hash = _bitcoin_message_hash(message)
    return private_key.sign(msg_hash, hasher=None)


def _pad_signature(sig_der: bytes, target_len: int = 72) -> bytes:
    """Pad DER signature to fixed length for wire format."""
    if len(sig_der) > target_len:
        raise ValueError(f"Signature too long: {len(sig_der)} > {target_len}")
    return sig_der.rjust(target_len, b"\xff")


def create_bond_proof_our_implementation(
    privkey: PrivateKey,
    pubkey: bytes,
    maker_nick: str,
    taker_nick: str,
    txid: str,
    vout: int,
    locktime: int,
    cert_expiry_blocks: int = 2016 * 52,
) -> str:
    """Create bond proof using our implementation logic."""
    cert_pub = pubkey
    utxo_pub = pubkey
    cert_expiry_encoded = cert_expiry_blocks // 2016

    # 1. Nick signature - signs "(taker_nick|maker_nick)"
    nick_msg = (taker_nick + "|" + maker_nick).encode("ascii")
    nick_sig = _sign_message_bitcoin(privkey, nick_msg)
    nick_sig_padded = _pad_signature(nick_sig, 72)

    # 2. Certificate signature - self-signed
    cert_msg = (
        b"fidelity-bond-cert|"
        + cert_pub
        + b"|"
        + str(cert_expiry_encoded).encode("ascii")
    )
    cert_sig = _sign_message_bitcoin(privkey, cert_msg)
    cert_sig_padded = _pad_signature(cert_sig, 72)

    # 3. Pack the proof
    txid_bytes = bytes.fromhex(txid)
    proof_data = struct.pack(
        "<72s72s33sH33s32sII",
        nick_sig_padded,
        cert_sig_padded,
        cert_pub,
        cert_expiry_encoded,
        utxo_pub,
        txid_bytes,
        vout,
        locktime,
    )

    return base64.b64encode(proof_data).decode("ascii")


def test_bond_proof_validates_with_reference_implementation():
    """
    Test that bond proofs created with our implementation can be validated
    by the reference implementation's FidelityBondProof parser.

    This is the critical compatibility test - if this passes, it means
    reference orderbook watchers SHOULD be able to validate our bonds.
    """
    # Import reference implementation
    try:
        import sys
        import os

        ref_path = os.path.join(
            os.path.dirname(__file__), "../../joinmarket-clientserver/src"
        )
        if ref_path not in sys.path:
            sys.path.insert(0, ref_path)
        from jmclient.fidelity_bond import FidelityBondProof
    except ImportError as e:
        pytest.skip(f"Reference implementation not available: {e}")

    # Create test bond
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    maker_nick = "J52TestMaker"
    taker_nick = "J5TestTaker"
    txid = "a" * 64
    vout = 0
    locktime = 1768435200

    # Create proof using our implementation
    our_proof = create_bond_proof_our_implementation(
        privkey=privkey,
        pubkey=pubkey,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        txid=txid,
        vout=vout,
        locktime=locktime,
    )

    assert len(our_proof) == 336  # base64 of 252 bytes

    # Validate with reference implementation
    validated_proof = FidelityBondProof.parse_and_verify_proof_msg(
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        data=our_proof,
    )

    # Verify all fields match
    assert validated_proof.maker_nick == maker_nick
    assert validated_proof.taker_nick == taker_nick
    assert validated_proof.utxo[0] == bytes.fromhex(txid)
    assert validated_proof.utxo[1] == vout
    assert validated_proof.locktime == locktime
    assert validated_proof.cert_pub == pubkey
    assert validated_proof.utxo_pub == pubkey


@pytest.mark.parametrize(
    "maker_nick,taker_nick",
    [
        ("J52MakerTest1", "J5TakerTest1"),
        ("J52jbDvERjd3N4Mr", "J5aXc5pemjkLbhAO"),  # Real mainnet nicks from logs
        ("J5ShortNick", "J5AnotherOne"),
    ],
)
def test_bond_proof_with_various_nicks(maker_nick: str, taker_nick: str):
    """Test bond proofs with various nick combinations, including real mainnet nicks."""
    try:
        import sys
        import os

        ref_path = os.path.join(
            os.path.dirname(__file__), "../../joinmarket-clientserver/src"
        )
        if ref_path not in sys.path:
            sys.path.insert(0, ref_path)
        from jmclient.fidelity_bond import FidelityBondProof
    except ImportError as e:
        pytest.skip(f"Reference implementation not available: {e}")

    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    our_proof = create_bond_proof_our_implementation(
        privkey=privkey,
        pubkey=pubkey,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        txid="b" * 64,
        vout=1,
        locktime=1800000000,
    )

    # Should validate successfully
    validated_proof = FidelityBondProof.parse_and_verify_proof_msg(
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        data=our_proof,
    )

    assert validated_proof.maker_nick == maker_nick
    assert validated_proof.taker_nick == taker_nick
