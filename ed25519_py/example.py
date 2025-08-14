#!/usr/bin/env python3
"""Example usage of the Ed25519 implementation."""

import binascii

from .key_generation import derive_public_key, generate_keypair
from .signing import sign, sign_resistant
from .verification import batch_verify, verify


def main():
    print("Ed25519 Pure Python Implementation - Example Usage")
    print("=" * 60)

    # 1. Generate a keypair
    print("\n1. Generating keypair...")
    private_key, public_key = generate_keypair()
    print(f"   Private key: {binascii.hexlify(private_key).decode()[:32]}...")
    print(f"   Public key:  {binascii.hexlify(public_key).decode()}")

    # 2. Sign a message
    print("\n2. Signing a message...")
    message = b"Hello, Ed25519! This is a test message."
    print(f"   Message: {message.decode()}")

    signature = sign(private_key, message)
    print(f"   Signature: {binascii.hexlify(signature).decode()[:64]}...")

    # 3. Verify the signature
    print("\n3. Verifying the signature...")
    is_valid = verify(public_key, signature, message)
    print(f"   ✓ Signature is {'valid' if is_valid else 'invalid'}")

    # 4. Try to verify with wrong message
    print("\n4. Testing with wrong message...")
    wrong_message = b"This is a different message"
    is_valid = verify(public_key, signature, wrong_message)
    print(f"   ✗ Wrong message verification: {'valid' if is_valid else 'invalid (expected)'}")

    # 5. Batch verification example
    print("\n5. Batch verification example...")
    print("   Generating 3 keypairs and signatures...")

    keypairs = []
    signatures = []
    messages = []

    for i in range(3):
        priv, pub = generate_keypair()
        keypairs.append((priv, pub))
        msg = f"Message {i + 1}".encode()
        messages.append(msg)
        sig = sign(priv, msg)
        signatures.append(sig)
        print(f"   - Keypair {i + 1} generated and message signed")

    public_keys = [kp[1] for kp in keypairs]

    print("   Verifying batch...")
    batch_valid = batch_verify(public_keys, signatures, messages)
    print(f"   ✓ Batch verification: {'all valid' if batch_valid else 'failed'}")

    # 6. Test deterministic signatures
    print("\n6. Testing deterministic signatures...")
    sig1 = sign(private_key, message)
    sig2 = sign(private_key, message)
    deterministic = sig1 == sig2
    print(
        f"   ✓ Signatures are {'deterministic' if deterministic else 'not deterministic (error!)'}"
    )

    # 7. Demonstrate key derivation
    print("\n7. Public key derivation...")
    derived_public = derive_public_key(private_key)
    matches = derived_public == public_key
    print(f"   ✓ Derived public key {'matches' if matches else 'does not match (error!)'}")

    # 8. Test side-channel resistant signing
    print("\n8. Testing side-channel resistant signing...")
    resistant_sig = sign_resistant(private_key, message)
    resistant_valid = verify(public_key, resistant_sig, message)
    print(f"   ✓ Resistant signature is {'valid' if resistant_valid else 'invalid'}")
    # Resistant signatures are still deterministic
    matches_regular = resistant_sig == signature
    print(
        f"   ✓ Resistant signature {'matches' if matches_regular else 'differs from'} regular signature"
    )
    print("   Note: Scalar splitting randomizes computations to prevent side-channel leaks")

    print("\n" + "=" * 60)
    print("Example completed successfully!")


if __name__ == "__main__":
    main()
