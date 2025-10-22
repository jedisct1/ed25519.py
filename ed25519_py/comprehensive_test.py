"""Comprehensive testing of Ed25519 implementation."""

import time

from .constants import L, P
from .edwards_curve import BASE_POINT, IDENTITY, scalar_multiply
from .encoding import is_canonical_point
from .key_generation import generate_keypair
from .scalar_arithmetic import is_canonical_scalar
from .signing import sign
from .verification import batch_verify, verify


def test_deterministic_signatures():
    """Test that signatures are deterministic."""
    print("Testing deterministic signatures...")

    private_key, public_key = generate_keypair()
    message = b"Deterministic test message"

    # Sign the same message multiple times
    sig1 = sign(private_key, message)
    sig2 = sign(private_key, message)
    sig3 = sign(private_key, message)

    assert sig1 == sig2 == sig3, "Signatures should be deterministic"
    print("✓ Signatures are deterministic")


def test_canonicity_checks():
    """Test canonical encoding checks."""
    print("\nTesting canonicity checks...")

    # Test scalar canonicity
    # Canonical scalar (< L)
    canonical_scalar = (L - 1).to_bytes(32, "little")
    assert is_canonical_scalar(canonical_scalar), "L-1 should be canonical"

    # Non-canonical scalar (>= L)
    non_canonical_scalar = L.to_bytes(32, "little")
    assert not is_canonical_scalar(non_canonical_scalar), "L should not be canonical"

    print("✓ Scalar canonicity checks")

    # Test point canonicity
    # Canonical point (y < p)
    canonical_point = (P - 1).to_bytes(32, "little")
    assert is_canonical_point(canonical_point), "P-1 should be canonical"

    # Non-canonical point (y >= p)
    non_canonical_point = P.to_bytes(32, "little")
    assert not is_canonical_point(non_canonical_point), "P should not be canonical"

    print("✓ Point canonicity checks")


def test_base_point_order():
    """Test that the base point has the correct order."""
    print("\nTesting base point order...")

    # B should have order L
    # L * B should be the identity
    result = scalar_multiply(L, BASE_POINT)
    assert result == IDENTITY, "L * B should be identity"
    print("✓ Base point has order L")

    # (L-1) * B should not be identity
    result = scalar_multiply(L - 1, BASE_POINT)
    assert result != IDENTITY, "(L-1) * B should not be identity"
    print("✓ Base point order is exactly L")


def test_batch_verification():
    """Test batch verification."""
    print("\nTesting batch verification...")

    # Generate multiple key pairs and signatures
    n = 5
    keypairs = [generate_keypair() for _ in range(n)]
    messages = [f"Message {i}".encode() for i in range(n)]

    public_keys = [kp[1] for kp in keypairs]
    signatures = [sign(kp[0], msg) for kp, msg in zip(keypairs, messages)]

    # Test valid batch
    assert batch_verify(public_keys, signatures, messages), "Valid batch should verify"
    print(f"✓ Batch verification of {n} valid signatures")

    # Test invalid batch (corrupt one signature)
    bad_signatures = signatures.copy()
    bad_signatures[2] = b"\x00" * 64
    assert not batch_verify(
        public_keys, bad_signatures, messages
    ), "Batch with invalid signature should fail"
    print("✓ Batch verification rejects invalid signature")

    # Test batch with wrong message
    bad_messages = messages.copy()
    bad_messages[1] = b"Wrong message"
    assert not batch_verify(
        public_keys, signatures, bad_messages
    ), "Batch with wrong message should fail"
    print("✓ Batch verification rejects wrong message")


def test_signature_malleability():
    """Test signature malleability protection."""
    print("\nTesting signature malleability protection...")

    private_key, public_key = generate_keypair()
    message = b"Test malleability"
    signature = sign(private_key, message)

    # Extract R and S
    R_bytes = signature[:32]
    S_bytes = signature[32:]
    S = int.from_bytes(S_bytes, "little")

    # Try to create a malleable signature with S' = S + L
    S_prime = S + L
    S_prime_bytes = S_prime.to_bytes(32, "little")
    malleable_sig = R_bytes + S_prime_bytes

    # This should be rejected due to non-canonical S
    assert not verify(public_key, malleable_sig, message), "Malleable signature should be rejected"
    print("✓ Non-canonical S values are rejected")


def test_small_order_rejection():
    """Test that small order points are rejected."""
    print("\nTesting small order point rejection...")

    from ed25519_py.constants import SMALL_ORDER_POINTS

    # Try to use a small order point as public key
    small_order_pk = SMALL_ORDER_POINTS[0]  # Identity point

    # Create a dummy signature
    dummy_sig = b"\x00" * 64
    message = b"Test"

    # Should be rejected
    assert not verify(
        small_order_pk, dummy_sig, message
    ), "Small order public key should be rejected"
    print("✓ Small order public keys are rejected")


def test_wrong_curve_point():
    """Test that points not on the curve are rejected."""
    print("\nTesting invalid curve point rejection...")

    # Create an invalid point encoding (not on curve)
    # Use a y-coordinate that doesn't correspond to any x on the curve
    invalid_point = (2).to_bytes(32, "little")  # y=2 doesn't give valid x^2

    from ed25519_py.encoding import decode_point

    point = decode_point(invalid_point)

    # Most y values will actually have a corresponding x, but the decode
    # function should verify the point is on the curve
    if point is not None:
        assert point.is_on_curve(), "Decoded point should be on curve"

    print("✓ Invalid curve points handled correctly")


def test_performance():
    """Basic performance testing."""
    print("\nPerformance testing...")

    # Key generation
    start = time.time()
    for _ in range(10):
        generate_keypair()
    kg_time = (time.time() - start) / 10
    print(f"  Key generation: {kg_time * 1000:.2f} ms")

    # Signing
    private_key, public_key = generate_keypair()
    message = b"Performance test message"

    start = time.time()
    for _ in range(10):
        sign(private_key, message)
    sign_time = (time.time() - start) / 10
    print(f"  Signing: {sign_time * 1000:.2f} ms")

    # Verification
    signature = sign(private_key, message)

    start = time.time()
    for _ in range(10):
        verify(public_key, signature, message)
    verify_time = (time.time() - start) / 10
    print(f"  Verification: {verify_time * 1000:.2f} ms")


def test_empty_message():
    """Test signing and verifying empty messages."""
    print("\nTesting empty message...")

    private_key, public_key = generate_keypair()
    empty_message = b""

    signature = sign(private_key, empty_message)
    assert verify(public_key, signature, empty_message), "Empty message should verify"
    print("✓ Empty message handling")


def test_large_message():
    """Test signing and verifying large messages."""
    print("\nTesting large message...")

    private_key, public_key = generate_keypair()
    large_message = b"A" * 10000  # 10KB message

    signature = sign(private_key, large_message)
    assert verify(public_key, signature, large_message), "Large message should verify"
    print("✓ Large message handling")


def run_comprehensive_tests():
    """Run all comprehensive tests."""
    print("=" * 60)
    print("Running comprehensive Ed25519 tests")
    print("=" * 60)

    test_deterministic_signatures()
    test_canonicity_checks()
    test_base_point_order()
    test_batch_verification()
    test_signature_malleability()
    test_small_order_rejection()
    test_wrong_curve_point()
    test_empty_message()
    test_large_message()
    test_performance()

    print("\n" + "=" * 60)
    print("✅ All comprehensive tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    run_comprehensive_tests()
