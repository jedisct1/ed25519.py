#!/usr/bin/env python3
"""Test the ed25519_py package from outside."""

from ed25519_py import batch_verify, generate_keypair, sign, verify


def test_basic():
    """Test basic functionality."""
    print("Testing Ed25519 package...")

    # Generate keypair
    private_key, public_key = generate_keypair()
    print("✓ Generated keypair")

    # Sign message
    message = b"Test message for package"
    signature = sign(private_key, message)
    print("✓ Signed message")

    # Verify signature
    assert verify(public_key, signature, message)
    print("✓ Verified signature")

    # Test batch verification
    keys = []
    sigs = []
    msgs = []
    for i in range(3):
        priv, pub = generate_keypair()
        msg = f"Message {i}".encode()
        sig = sign(priv, msg)
        keys.append(pub)
        sigs.append(sig)
        msgs.append(msg)

    assert batch_verify(keys, sigs, msgs)
    print("✓ Batch verification works")

    print("\n✅ All package tests passed!")


if __name__ == "__main__":
    test_basic()
