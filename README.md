# Ed25519 Pure Python Implementation

A pure Python implementation of the Ed25519 digital signature scheme, following the specification from "Taming the many EdDSAs" paper. This implementation provides the highest security level with both SUF-CMA (Strong Unforgeability under Chosen Message Attack) and SBS (Strongly Binding Signatures) properties.

## Features

- **Pure Python**: No external cryptographic dependencies (except `hashlib` for SHA-512)
- **Complete**: Includes key generation, signing, verification, and batch verification
- **Well-tested**: Verified against RFC 8032 test vectors
- **Standards compliant**: Follows the Ed25519 specification
- **Side-channel resistant**: Optional signing functions with protection against timing attacks

## Security Properties

This implementation provides:

1. **SUF-CMA Security**: Rejects non-canonical scalar encodings (S ≥ L)
2. **SBS Security**: Rejects small order public keys (order 1, 2, 4, or 8)
3. **Canonical Validation**: Rejects non-canonical point encodings
4. **Cofactored Verification**: Uses the equation `8(S·B) = 8R + 8(h·A)` for compatibility with batch verification

## Installation

Simply copy the `ed25519-py` directory to your project.

## Usage

### Basic Usage

```python
from ed25519_py import generate_keypair, sign, verify

# Generate a keypair
private_key, public_key = generate_keypair()

# Sign a message
message = b"Hello, Ed25519!"
signature = sign(private_key, message)

# Verify the signature
is_valid = verify(public_key, signature, message)
print(f"Signature valid: {is_valid}")

# Batch verification
from ed25519_py import batch_verify

public_keys = [pk1, pk2, pk3]
signatures = [sig1, sig2, sig3]
messages = [msg1, msg2, msg3]

all_valid = batch_verify(public_keys, signatures, messages)
```

### Side-Channel Resistant Signing

For applications that require protection against timing and power analysis attacks:

```python
from ed25519_py import sign_resistant

# Generate a side-channel resistant signature
signature = sign_resistant(private_key, message)

# Verify with standard verification (fully compatible)
is_valid = verify(public_key, signature, message)
```

The resistant signing functions use:
- **Scalar splitting**: Splits scalar multiplication into randomized parts
- **Coordinate randomization**: Randomizes projective coordinates during point operations
- **~50% performance overhead**: Acceptable trade-off for enhanced security
- **Deterministic output**: Same signature for same input (maintains Ed25519 properties)

## API Reference

### Key Generation

```python
def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.
    Returns (private_key, public_key) as 32-byte arrays."""

def derive_public_key(private_key: bytes) -> bytes:
    """Derive the public key from a private key."""
```

### Signing

```python
def sign(private_key: bytes, message: bytes) -> bytes:
    """Sign a message with an Ed25519 private key.
    Returns a 64-byte signature."""

def sign_resistant(private_key: bytes, message: bytes) -> bytes:
    """Sign with side-channel resistance using scalar splitting.
    Returns a 64-byte signature (compatible with standard verification)."""

def sign_with_expanded_key_resistant(
    expanded_private_key: tuple[bytes, bytes],
    public_key: bytes,
    message: bytes) -> bytes:
    """Sign with an expanded key using side-channel resistant techniques."""
```

### Verification

```python
def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature (SUF-CMA + SBS secure)."""

def verify_cofactorless(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify using cofactorless equation (less secure, for compatibility only)."""

def batch_verify(public_keys: list[bytes], signatures: list[bytes],
                messages: list[bytes]) -> bool:
    """Batch verification of multiple signatures."""
```

## Testing

Run the test suite to verify the implementation:

```bash
# Run RFC 8032 test vectors
python3 -m ed25519_py.test_vectors

# Run comprehensive tests
python3 -m ed25519_py.comprehensive_test

# Run side-channel resistant signing tests
python3 -m ed25519_py.test_resistant_signing

# Run the example script
python3 -m ed25519_py.example
```

All tests should pass, confirming compliance with the Ed25519 specification.