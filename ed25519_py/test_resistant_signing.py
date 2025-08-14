"""Tests for side-channel resistant signing functions."""

import hashlib
import time

from .key_generation import derive_public_key, expand_private_key, generate_keypair
from .signing import sign, sign_resistant, sign_with_expanded_key_resistant
from .verification import verify


def test_resistant_signing_compatibility():
    """Test that resistant signatures are compatible with regular verification."""
    print("Testing resistant signing compatibility...")

    # Generate test keypair
    private_key, public_key = generate_keypair()
    message = b"Test message for resistant signing"

    # Create signatures using both methods
    regular_sig = sign(private_key, message)
    resistant_sig = sign_resistant(private_key, message)

    # Both signatures should verify correctly
    assert verify(public_key, regular_sig, message), "Regular signature failed to verify"
    assert verify(public_key, resistant_sig, message), "Resistant signature failed to verify"

    # Both should be valid Ed25519 signatures
    print("✓ Resistant signatures are compatible with regular verification")


def test_resistant_expanded_key_signing():
    """Test resistant signing with expanded keys."""
    print("Testing resistant signing with expanded keys...")

    # Generate test keypair
    private_key, public_key = generate_keypair()
    message = b"Test message for expanded key resistance"

    # Expand the private key
    expanded_key = expand_private_key(private_key)

    # Sign with expanded key using resistant method
    resistant_sig = sign_with_expanded_key_resistant(expanded_key, public_key, message)

    # Signature should verify correctly
    assert verify(
        public_key, resistant_sig, message
    ), "Resistant expanded key signature failed to verify"

    print("✓ Resistant expanded key signatures verify correctly")


def test_resistant_signing_produces_valid_signatures():
    """Test that resistant signing produces valid Ed25519 signatures.

    Note: With proper scalar splitting, signatures remain deterministic
    because the nonce r is still derived deterministically, we just compute
    r·B in a randomized way.
    """
    print("Testing resistant signing produces valid signatures...")

    # Generate test keypair
    private_key, public_key = generate_keypair()
    message = b"Test message for validation check"

    # Create multiple resistant signatures
    for _ in range(10):
        sig = sign_resistant(private_key, message)
        assert verify(public_key, sig, message), "Resistant signature failed to verify"

    # All signatures should still be deterministic
    sig1 = sign_resistant(private_key, message)
    sig2 = sign_resistant(private_key, message)

    # They should produce the same signature
    assert sig1 == sig2, "Resistant signatures should still be deterministic"

    print("✓ Resistant signing produces valid, deterministic signatures")


def test_resistant_signing_correctness():
    """Test that resistant signing produces correct Ed25519 signatures."""
    print("Testing resistant signing correctness with various messages...")

    # Generate test keypair
    private_key, public_key = generate_keypair()

    test_messages = [
        b"",  # Empty message
        b"a",  # Single byte
        b"Hello, World!",  # Short message
        b"The quick brown fox jumps over the lazy dog",  # Pangram
        b"\x00" * 64,  # Null bytes
        b"\xff" * 128,  # High bytes
        hashlib.sha512(b"long message").digest() * 100,  # Long message
    ]

    for i, message in enumerate(test_messages):
        # Create resistant signature
        resistant_sig = sign_resistant(private_key, message)

        # Verify the signature
        assert verify(
            public_key, resistant_sig, message
        ), f"Resistant signature failed for message {i}"

    print("✓ Resistant signing works correctly for various message types")


def test_resistant_signing_performance():
    """Test the performance impact of resistant signing."""
    print("Testing resistant signing performance...")

    # Generate test keypair
    private_key, public_key = generate_keypair()
    message = b"Performance test message"

    # Measure regular signing time
    start = time.time()
    for _ in range(100):
        sign(private_key, message)
    regular_time = time.time() - start

    # Measure resistant signing time
    start = time.time()
    for _ in range(100):
        sign_resistant(private_key, message)
    resistant_time = time.time() - start

    print(f"  Regular signing: {regular_time:.3f}s for 100 signatures")
    print(f"  Resistant signing: {resistant_time:.3f}s for 100 signatures")
    print(f"  Overhead: {(resistant_time/regular_time - 1)*100:.1f}%")

    # Resistant signing should not be excessively slower (allow up to 5x slower due to splitting)
    assert resistant_time < regular_time * 5, "Resistant signing is too slow"

    print("✓ Resistant signing performance is acceptable")


def test_resistant_signing_edge_cases():
    """Test resistant signing with edge cases."""
    print("Testing resistant signing edge cases...")

    # Test with maximum scalar values
    private_key = b"\xff" * 32  # Will be clamped/reduced
    public_key = derive_public_key(private_key)
    message = b"Edge case message"

    resistant_sig = sign_resistant(private_key, message)
    assert verify(public_key, resistant_sig, message), "Failed with max scalar value"

    # Test with minimum scalar values
    private_key = b"\x00" * 31 + b"\x01"  # Small but valid
    public_key = derive_public_key(private_key)

    resistant_sig = sign_resistant(private_key, message)
    assert verify(public_key, resistant_sig, message), "Failed with min scalar value"

    print("✓ Resistant signing handles edge cases correctly")


def run_all_tests():
    """Run all side-channel resistant signing tests."""
    print("\n=== Running Side-Channel Resistant Signing Tests ===\n")

    test_resistant_signing_compatibility()
    test_resistant_expanded_key_signing()
    test_resistant_signing_produces_valid_signatures()
    test_resistant_signing_correctness()
    test_resistant_signing_performance()
    test_resistant_signing_edge_cases()

    print("\n=== All Side-Channel Resistant Tests Passed ===\n")


if __name__ == "__main__":
    run_all_tests()
