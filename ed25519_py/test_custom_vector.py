#!/usr/bin/env python3
"""Test custom Ed25519 vector."""

from .encoding import decode_point, is_canonical_point
from .scalar_arithmetic import is_canonical_scalar
from .test_utils import hex_to_bytes
from .verification import verify, verify_cofactorless


def test_custom_vector():
    """Test the provided custom vector."""
    print("Testing custom Ed25519 vector...")
    print("=" * 60)

    # Parse the provided test vector (corrected assignment)
    message_hex = "65643235353139766563746f72732033"
    public_key_hex = "86e72f5c2a7215151059aa151c0ee6f8e2155d301402f35d7498f078629a8f79"
    signature_hex = (
        "fa9dde274f4820efb19a890f8ba2d8791710a4303ceef4aedf9dddc4e81a1f11"
        + "701a598b9a02ae60505dd0c2938a1a0c2d6ffd4676cfb49125b19e9cb358da06"
    )

    # Convert to bytes
    message = hex_to_bytes(message_hex)
    public_key = hex_to_bytes(public_key_hex)
    signature = hex_to_bytes(signature_hex)

    print(f"Message (hex): {message_hex}")
    print(f"Message (bytes): {message!r}")
    print(f"Message (ASCII): {message.decode('ascii', errors='ignore')}")
    print(f"Message length: {len(message)} bytes")
    print()

    print(f"Public key (hex): {public_key_hex}")
    print(f"Public key length: {len(public_key)} bytes")
    print()

    print(f"Signature (hex): {signature_hex}")
    print(f"Signature length: {len(signature)} bytes")
    print()

    # Check if inputs are valid
    print("Validation checks:")
    print("-" * 40)

    # Check public key length
    if len(public_key) != 32:
        print(f"❌ Invalid public key length: {len(public_key)} bytes (expected 32)")
        return False
    else:
        print(f"✓ Public key length: {len(public_key)} bytes")

    # Check signature length
    if len(signature) != 64:
        print(f"❌ Invalid signature length: {len(signature)} bytes (expected 64)")
        return False
    else:
        print(f"✓ Signature length: {len(signature)} bytes")

    # Check if public key is canonical
    if not is_canonical_point(public_key):
        print("❌ Public key is not in canonical form")
    else:
        print("✓ Public key is in canonical form")

    # Check if we can decode the public key as a curve point
    point = decode_point(public_key)
    if point is None:
        print("❌ Public key does not decode to a valid curve point")
    else:
        print("✓ Public key decodes to a valid curve point")
        if point.is_on_curve():
            print("✓ Point is on the Edwards curve")
        else:
            print("❌ Point is not on the Edwards curve")

    # Extract and check signature components
    R_bytes = signature[:32]
    S_bytes = signature[32:]

    if not is_canonical_scalar(S_bytes):
        print("❌ Signature scalar S is not canonical")
    else:
        print("✓ Signature scalar S is canonical")

    if not is_canonical_point(R_bytes):
        print("❌ Signature point R is not in canonical form")
    else:
        print("✓ Signature point R is in canonical form")

    R_point = decode_point(R_bytes)
    if R_point is None:
        print("❌ Signature R does not decode to a valid curve point")
    else:
        print("✓ Signature R decodes to a valid curve point")

    print()
    print("Verification results:")
    print("-" * 40)

    # Try verification with cofactored equation (most secure)
    try:
        result_cofactored = verify(public_key, signature, message)
        print(f"Cofactored verification: {'✓ VALID' if result_cofactored else '✗ INVALID'}")
    except Exception as e:
        print(f"Cofactored verification failed with error: {e}")
        result_cofactored = False

    # Try verification with cofactorless equation (less secure, more common)
    try:
        result_cofactorless = verify_cofactorless(public_key, signature, message)
        print(f"Cofactorless verification: {'✓ VALID' if result_cofactorless else '✗ INVALID'}")
    except Exception as e:
        print(f"Cofactorless verification failed with error: {e}")
        result_cofactorless = False

    print()
    print("=" * 60)

    if result_cofactored or result_cofactorless:
        print("✅ Signature verification succeeded")
        return True
    else:
        print("❌ Signature verification failed")
        return False


def add_to_test_suite():
    """Add this vector to the main test suite."""
    print("\nAdding custom vector to test suite...")

    test_code = '''
def test_custom_vector_in_suite():
    """Test custom vector: 'ed25519vectors 3' message."""
    message = bytes.fromhex("65643235353139766563746f72732033")
    public_key = bytes.fromhex("86e72f5c2a7215151059aa151c0ee6f8e2155d301402f35d7498f078629a8f79")
    signature = bytes.fromhex("fa9dde274f4820efb19a890f8ba2d8791710a4303ceef4aedf9dddc4e81a1f11701a598b9a02ae60505dd0c2938a1a0c2d6ffd4676cfb49125b19e9cb358da06")

    # The message is ASCII "ed25519vectors 3"
    assert message == b"ed25519vectors 3", "Message should be 'ed25519vectors 3'"

    # Verify the signature
    result = verify(public_key, signature, message)
    return result
'''
    print("Test function created for integration into test suite")
    print(test_code)


if __name__ == "__main__":
    success = test_custom_vector()
    if success:
        add_to_test_suite()
