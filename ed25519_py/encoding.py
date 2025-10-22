"""Encoding and decoding functions for Ed25519."""


from .constants import ALL_SMALL_ORDER_POINTS, D, P
from .edwards_curve import EdwardsPoint
from .field_arithmetic import (
    field_add,
    field_inv,
    field_is_negative,
    field_mul,
    field_sqrt,
    field_square,
    field_sub,
)
from .scalar_arithmetic import scalar_from_bytes, scalar_to_bytes


def encode_point(point: EdwardsPoint) -> bytes:
    """Encode an Edwards point as 32 bytes.
    Format: 255 bits for y-coordinate (little-endian) + 1 sign bit for x.
    """
    y_bytes = point.y.to_bytes(32, "little")
    # Set the sign bit (bit 255) if x is negative (odd)
    if field_is_negative(point.x):
        y_bytes = y_bytes[:-1] + bytes([y_bytes[31] | 0x80])
    return y_bytes


def decode_point(point_bytes: bytes) -> EdwardsPoint | None:
    """Decode a point from 32 bytes.
    Returns None if the bytes don't represent a valid curve point.
    """
    if len(point_bytes) != 32:
        return None

    # Extract y coordinate and sign bit
    y = int.from_bytes(point_bytes, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1  # Clear the sign bit

    # Check if y is in valid range [0, p-1]
    if y >= P:
        return None

    # Recover x from the curve equation: x^2 = (y^2 - 1) / (d*y^2 + 1)
    y2 = field_square(y)
    numerator = field_sub(y2, 1)
    denominator = field_add(field_mul(D, y2), 1)

    if denominator == 0:
        return None

    x2 = field_mul(numerator, field_inv(denominator))

    # Compute square root of x^2
    x = field_sqrt(x2)
    if x is None:
        return None

    # Choose the correct sign for x
    if field_is_negative(x) != sign:
        x = P - x

    return EdwardsPoint(x, y)


encode_scalar = scalar_to_bytes
decode_scalar = scalar_from_bytes


def is_canonical_point(point_bytes: bytes) -> bool:
    """Check if point encoding is canonical.
    Optimized check from the paper (Listing 1.2).
    A point is canonical if its y-coordinate is < p = 2^255 - 19.
    """
    if len(point_bytes) != 32:
        return False

    # Fast path: if first byte < 237, definitely canonical
    # This works because if point_bytes[0] < 237, then the entire
    # number is definitely less than 2^255 - 19
    if point_bytes[0] < 237:
        return True

    # Extract y coordinate (without sign bit)
    y = int.from_bytes(point_bytes, "little")
    y &= (1 << 255) - 1  # Clear the sign bit

    # Check if y < p
    return y < P


def is_small_order_point_bytes(point_bytes: bytes) -> bool:
    """Check if point bytes represent a small order point.
    This includes both canonical and non-canonical encodings.
    """
    return point_bytes in ALL_SMALL_ORDER_POINTS


def validate_point_bytes(point_bytes: bytes) -> bool:
    """Validate that point bytes are acceptable for verification.
    Rejects:
    1. Non-canonical encodings
    2. Small order points
    3. Invalid curve points
    """
    if not is_canonical_point(point_bytes):
        return False

    if is_small_order_point_bytes(point_bytes):
        return False

    point = decode_point(point_bytes)
    if point is None:
        return False

    return point.is_on_curve()
