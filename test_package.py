#!/usr/bin/env python3
"""Test that the ed25519_py package can be imported and used correctly."""

import sys


def test_package_imports():
    """Test that all main exports are available."""
    print("Testing package imports...")

    # Test main module import
    try:
        import ed25519_py

        print("✓ Package ed25519_py imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import ed25519_py: {e}")
        return False

    # Test that main functions are available
    required_functions = [
        "generate_keypair",
        "sign",
        "verify",
        "derive_public_key",
        "batch_verify",
        "sign_resistant",
    ]

    for func_name in required_functions:
        if hasattr(ed25519_py, func_name):
            print(f"✓ Function {func_name} is available")
        else:
            print(f"✗ Function {func_name} is not available")
            return False

    return True


def test_basic_operations():
    """Test basic Ed25519 operations work."""
    from ed25519_py import derive_public_key, generate_keypair, sign, verify

    print("\nTesting basic operations...")

    try:
        # Generate a keypair
        private_key, public_key = generate_keypair()
        print("✓ Keypair generation works")

        # Test public key derivation
        derived_public = derive_public_key(private_key)
        assert derived_public == public_key, "Public key derivation mismatch"
        print("✓ Public key derivation works")

        # Sign a message
        message = b"Test message for package verification"
        signature = sign(private_key, message)
        print("✓ Signing works")

        # Verify the signature
        is_valid = verify(public_key, signature, message)
        assert is_valid, "Signature verification failed"
        print("✓ Verification works")

        # Test invalid signature rejection
        wrong_message = b"Different message"
        is_invalid = verify(public_key, signature, wrong_message)
        assert not is_invalid, "Wrong message should not verify"
        print("✓ Invalid signature rejection works")

        return True

    except Exception as e:
        print(f"✗ Basic operations test failed: {e}")
        return False


def main():
    """Run all package tests."""
    print("=" * 60)
    print("Ed25519 Package Test")
    print("=" * 60)

    all_passed = True

    # Test imports
    if not test_package_imports():
        all_passed = False

    # Test basic operations
    if not test_basic_operations():
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("✅ All package tests passed!")
        print("=" * 60)
        return 0
    else:
        print("❌ Some package tests failed!")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())