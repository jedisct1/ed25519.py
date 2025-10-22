#!/usr/bin/env python3
"""Test that the ed25519_py package can be imported and used correctly."""

import sys


def test_package_imports():
    """Test that all main exports are available."""
    print("Testing package imports...")

    try:
        import ed25519_py
    except ImportError as e:
        print(f"✗ Failed to import ed25519_py: {e}")
        raise AssertionError("ed25519_py should import successfully") from e

    print("✓ Package ed25519_py imported successfully")

    required_functions = [
        "generate_keypair",
        "sign",
        "verify",
        "derive_public_key",
        "batch_verify",
        "sign_resistant",
    ]

    missing = [name for name in required_functions if not hasattr(ed25519_py, name)]
    for func_name in required_functions:
        if func_name not in missing:
            print(f"✓ Function {func_name} is available")
        else:
            print(f"✗ Function {func_name} is not available")

    assert not missing, f"Missing expected exports: {', '.join(missing)}"


def test_basic_operations():
    """Test basic Ed25519 operations work."""
    from ed25519_py import derive_public_key, generate_keypair, sign, verify

    print("\nTesting basic operations...")

    try:
        private_key, public_key = generate_keypair()
        print("✓ Keypair generation works")

        derived_public = derive_public_key(private_key)
        assert derived_public == public_key, "Public key derivation mismatch"
        print("✓ Public key derivation works")

        message = b"Test message for package verification"
        signature = sign(private_key, message)
        print("✓ Signing works")

        is_valid = verify(public_key, signature, message)
        assert is_valid, "Signature verification failed"
        print("✓ Verification works")

        wrong_message = b"Different message"
        is_invalid = verify(public_key, signature, wrong_message)
        assert not is_invalid, "Wrong message should not verify"
        print("✓ Invalid signature rejection works")

    except Exception as e:
        print(f"✗ Basic operations test failed: {e}")
        raise


def main():
    """Run all package tests."""
    print("=" * 60)
    print("Ed25519 Package Test")
    print("=" * 60)

    all_passed = True
    for test_func in (test_package_imports, test_basic_operations):
        try:
            test_func()
        except AssertionError as e:
            all_passed = False
            print(f"{test_func.__name__} failed: {e}")
        except Exception as e:
            all_passed = False
            print(f"{test_func.__name__} raised an unexpected error: {e}")

    print("\n" + "=" * 60)
    if all_passed:
        print("✅ All package tests passed!")
        print("=" * 60)
        return 0

    print("❌ Some package tests failed!")
    print("=" * 60)
    return 1


if __name__ == "__main__":
    sys.exit(main())
