"""Signature verification for Ed25519."""

import hashlib

from .constants import COFACTOR, L
from .edwards_curve import BASE_POINT, IDENTITY, point_add, scalar_multiply
from .encoding import (
    decode_point,
    decode_scalar,
    is_canonical_point,
    is_small_order_point_bytes,
)
from .scalar_arithmetic import is_canonical_scalar, scalar_reduce


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature (SUF-CMA + SBS secure).

    Algorithm 2 from the paper (cofactored verification):
    1. Reject if S ∉ {0, ..., L-1} (not canonical)
    2. Reject if public key A is a small order point
    3. Reject if A or R are non-canonical encodings
    4. Compute h = SHA512(R || A || M) mod L
    5. Accept if 8(S·B) - 8R - 8(h·A) = 0

    This implements the most secure variant with both SUF-CMA and SBS properties.
    """
    # Check signature length
    if len(signature) != 64:
        return False

    # Check public key length
    if len(public_key) != 32:
        return False

    # Extract R and S from signature
    R_bytes = signature[:32]
    S_bytes = signature[32:]

    # Step 1: Reject if S >= L (SUF-CMA security)
    if not is_canonical_scalar(S_bytes):
        return False

    S = decode_scalar(S_bytes)

    # Step 2: Reject small order public key (SBS security)
    if is_small_order_point_bytes(public_key):
        return False

    # Step 3: Reject non-canonical encodings
    if not is_canonical_point(public_key):
        return False

    if not is_canonical_point(R_bytes):
        return False

    # Decode points
    A = decode_point(public_key)
    R = decode_point(R_bytes)

    if A is None or R is None:
        return False

    # Verify points are on the curve
    if not A.is_on_curve() or not R.is_on_curve():
        return False

    # Step 4: Compute hash h = SHA512(R || A || M) mod L
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)

    # Step 5: Cofactored verification: 8(S·B) = 8R + 8(h·A)
    # Equivalently: 8(S·B) - 8R - 8(h·A) = 0

    # Compute left side: 8(S·B)
    SB = scalar_multiply(S, BASE_POINT)
    left = scalar_multiply(COFACTOR, SB)

    # Compute right side: 8R + 8(h·A)
    R8 = scalar_multiply(COFACTOR, R)
    hA = scalar_multiply(h, A)
    hA8 = scalar_multiply(COFACTOR, hA)
    right = point_add(R8, hA8)

    # Check if they are equal
    return bool(left == right)


def verify_cofactorless(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature using cofactorless verification.

    This is the verification equation used by most implementations:
    S·B = R + h·A

    Note: This is less secure than cofactored verification and should
    generally not be used. It's included for compatibility testing.
    """
    # Check signature length
    if len(signature) != 64:
        return False

    # Check public key length
    if len(public_key) != 32:
        return False

    # Extract R and S from signature
    R_bytes = signature[:32]
    S_bytes = signature[32:]

    # Reject if S >= L
    if not is_canonical_scalar(S_bytes):
        return False

    S = decode_scalar(S_bytes)

    # Reject non-canonical encodings
    if not is_canonical_point(public_key):
        return False

    if not is_canonical_point(R_bytes):
        return False

    # Decode points
    A = decode_point(public_key)
    R = decode_point(R_bytes)

    if A is None or R is None:
        return False

    # Compute hash h = SHA512(R || A || M) mod L
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)

    # Cofactorless verification: S·B = R + h·A
    left = scalar_multiply(S, BASE_POINT)
    hA = scalar_multiply(h, A)
    right = point_add(R, hA)

    return bool(left == right)


def batch_verify(public_keys: list[bytes], signatures: list[bytes], messages: list[bytes]) -> bool:
    """Batch verification of Ed25519 signatures.

    Algorithm 3 from the paper:
    1. Reject batch if any signature fails basic checks
    2. Sample random 128-bit coefficients z_i
    3. Compute h_i = SHA512(R_i || A_i || M_i) mod L
    4. Accept if 8(-Σz_i·S_i mod L)·B + 8(Σz_i·R_i) + 8(Σ(z_i·h_i mod L)·A_i) = 0

    This uses cofactored verification for security.
    """
    import secrets

    n = len(public_keys)
    if n == 0:
        return True

    if len(signatures) != n or len(messages) != n:
        raise ValueError("Lists must have the same length")

    # Step 1: Perform individual checks on each signature
    z_values = []
    h_values = []
    S_values = []
    R_points = []
    A_points = []

    for i in range(n):
        # Check lengths
        if len(signatures[i]) != 64 or len(public_keys[i]) != 32:
            return False

        R_bytes = signatures[i][:32]
        S_bytes = signatures[i][32:]

        # Check S is canonical
        if not is_canonical_scalar(S_bytes):
            return False

        # Check public key is not small order
        if is_small_order_point_bytes(public_keys[i]):
            return False

        # Check canonical encodings
        if not is_canonical_point(public_keys[i]):
            return False

        if not is_canonical_point(R_bytes):
            return False

        # Decode points
        A = decode_point(public_keys[i])
        R = decode_point(R_bytes)

        if A is None or R is None:
            return False

        # Store values
        S_values.append(decode_scalar(S_bytes))
        R_points.append(R)
        A_points.append(A)

        # Compute h_i
        hash_input = R_bytes + public_keys[i] + messages[i]
        h_hash = hashlib.sha512(hash_input).digest()
        h = int.from_bytes(h_hash, "little")
        h_values.append(scalar_reduce(h))

        # Sample random z_i (128 bits)
        z = int.from_bytes(secrets.token_bytes(16), "little")
        z_values.append(z)

    # Step 2: Compute the batch equation
    # 8(-Σz_i·S_i mod L)·B + 8(Σz_i·R_i) + 8(Σ(z_i·h_i mod L)·A_i) = 0

    # Compute -Σz_i·S_i mod L
    sum_zS = 0
    for i in range(n):
        sum_zS = (sum_zS + z_values[i] * S_values[i]) % L
    neg_sum_zS = (-sum_zS) % L

    # Compute 8(-Σz_i·S_i mod L)·B
    term1 = scalar_multiply(COFACTOR * neg_sum_zS, BASE_POINT)

    # Compute 8(Σz_i·R_i)
    sum_zR = IDENTITY
    for i in range(n):
        zR = scalar_multiply(z_values[i], R_points[i])
        sum_zR = point_add(sum_zR, zR)
    term2 = scalar_multiply(COFACTOR, sum_zR)

    # Compute 8(Σ(z_i·h_i mod L)·A_i)
    sum_zhA = IDENTITY
    for i in range(n):
        zh = (z_values[i] * h_values[i]) % L
        zhA = scalar_multiply(zh, A_points[i])
        sum_zhA = point_add(sum_zhA, zhA)
    term3 = scalar_multiply(COFACTOR, sum_zhA)

    # Check if sum equals identity
    result = point_add(term1, point_add(term2, term3))

    return bool(result == IDENTITY)
