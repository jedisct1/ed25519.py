"""Edwards curve operations for Ed25519."""
from typing import Optional

from .constants import B_X, B_Y, D, P
from .field_arithmetic import (
    field_add,
    field_inv,
    field_is_negative,
    field_mul,
    field_neg,
    field_reduce,
    field_sqrt,
    field_square,
    field_sub,
)


class EdwardsPoint:
    """Point on the twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2."""

    def __init__(self, x: int, y: int, z: int = 1, t: Optional[int] = None):
        """Initialize a point with coordinates.

        Can use either:
        - Affine coordinates (x, y)
        - Extended coordinates (x, y, z, t) where x=X/Z, y=Y/Z, t=T/Z=XY/Z
        """
        self.x = field_reduce(x)
        self.y = field_reduce(y)
        self.z = field_reduce(z)
        # T coordinate for extended representation (xy = t)
        if t is not None:
            self.t = field_reduce(t)
        else:
            # Calculate t = xy/z
            if z == 1:
                self.t = field_mul(self.x, self.y)
            else:
                xy = field_mul(self.x, self.y)
                self.t = field_mul(xy, field_inv(self.z))

    def __eq__(self, other):
        """Check if two points are equal (works with different Z coordinates)."""
        if not isinstance(other, EdwardsPoint):
            return False
        # For projective points: (X1/Z1, Y1/Z1) == (X2/Z2, Y2/Z2)
        # iff X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
        x1z2 = field_mul(self.x, other.z)
        x2z1 = field_mul(other.x, self.z)
        y1z2 = field_mul(self.y, other.z)
        y2z1 = field_mul(other.y, self.z)
        return x1z2 == x2z1 and y1z2 == y2z1

    def __repr__(self):
        """String representation of the point."""
        return f"EdwardsPoint({self.x}, {self.y})"

    def is_identity(self) -> bool:
        """Check if this is the identity point (0, 1)."""
        # In projective: (0, Z, Z) for any Z != 0
        return self.x == 0 and self.y == self.z

    def is_on_curve(self) -> bool:
        """Verify that the point is on the curve."""
        # In projective: -X^2*Z^2 + Y^2*Z^2 = Z^4 + d*X^2*Y^2
        x2 = field_square(self.x)
        y2 = field_square(self.y)
        z2 = field_square(self.z)
        z4 = field_square(z2)

        # Left side: Y^2*Z^2 - X^2*Z^2
        left = field_mul(field_sub(y2, x2), z2)
        # Right side: Z^4 + d*X^2*Y^2
        right = field_add(z4, field_mul(field_mul(D, x2), y2))
        return left == right

    def to_affine(self) -> tuple[int, int]:
        """Convert to affine coordinates (x, y)."""
        if self.z == 0:
            raise ValueError("Cannot convert point at infinity to affine")
        z_inv = field_inv(self.z)
        return (field_mul(self.x, z_inv), field_mul(self.y, z_inv))

    def randomize_z(self, random_z: int) -> "EdwardsPoint":
        """Randomize the Z coordinate for side-channel resistance.

        (X, Y, Z, T) -> (X*r, Y*r, Z*r, T*r) represents the same point.
        """
        if random_z == 0:
            raise ValueError("Random Z must be non-zero")
        r = field_reduce(random_z)
        return EdwardsPoint(
            field_mul(self.x, r),
            field_mul(self.y, r),
            field_mul(self.z, r),
            field_mul(self.t, r) if hasattr(self, "t") and self.t is not None else None,
        )


# Identity element
IDENTITY = EdwardsPoint(0, 1)

# Base point
BASE_POINT = EdwardsPoint(B_X, B_Y)


def point_add(P1: EdwardsPoint, P2: EdwardsPoint) -> EdwardsPoint:
    """Add two points on the Edwards curve.

    Uses the original affine formula for compatibility, but can be extended
    to use projective coordinates for side-channel resistance.
    """
    # Convert to affine if in projective
    if P1.z != 1:
        x1, y1 = P1.to_affine()
    else:
        x1, y1 = P1.x, P1.y

    if P2.z != 1:
        x2, y2 = P2.to_affine()
    else:
        x2, y2 = P2.x, P2.y

    # Compute intermediate values
    x1x2 = field_mul(x1, x2)
    y1y2 = field_mul(y1, y2)
    x1y2 = field_mul(x1, y2)
    x2y1 = field_mul(x2, y1)

    # Compute d*x1*x2*y1*y2
    dxy = field_mul(field_mul(D, x1x2), y1y2)

    # Compute x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    x3_num = field_add(x1y2, x2y1)
    x3_den = field_add(1, dxy)
    x3 = field_mul(x3_num, field_inv(x3_den))

    # Compute y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
    y3_num = field_add(y1y2, x1x2)
    y3_den = field_sub(1, dxy)
    y3 = field_mul(y3_num, field_inv(y3_den))

    return EdwardsPoint(x3, y3)


def point_double(P: EdwardsPoint) -> EdwardsPoint:
    """Double a point on the Edwards curve.
    This is just point addition with itself, but can be optimized.
    """
    return point_add(P, P)


def point_neg(P: EdwardsPoint) -> EdwardsPoint:
    """Negate a point: -(x, y) = (-x, y)."""
    return EdwardsPoint(field_neg(P.x), P.y)


def point_sub(P1: EdwardsPoint, P2: EdwardsPoint) -> EdwardsPoint:
    """Subtract two points: P1 - P2 = P1 + (-P2)."""
    return point_add(P1, point_neg(P2))


def scalar_multiply(k: int, P: EdwardsPoint) -> EdwardsPoint:
    """Multiply a point by a scalar using the double-and-add algorithm.
    This is a simple left-to-right binary method.
    Note: For production use, this should be constant-time.
    """
    if k == 0:
        return IDENTITY

    if k < 0:
        k = -k
        P = point_neg(P)

    # Binary representation of k
    result = IDENTITY
    addend = P

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result


def scalar_multiply_split(
    k: int, P: EdwardsPoint, split: Optional[tuple[int, int]] = None
) -> EdwardsPoint:
    """Multiply a point by a scalar using scalar splitting for side-channel resistance.

    Instead of computing k*P directly, we split k = k1 + k2 where k1 is random,
    then compute k*P = k1*P + k2*P. This randomizes the scalar multiplication.

    Args:
        k: The scalar to multiply by
        P: The point to multiply
        split: Optional (k1, k2) where k1 + k2 = k. If None, generates random split.

    Returns:
        The point k*P
    """
    if split is None:
        # Generate random split: k = k1 + k2
        import secrets

        from .constants import L

        # Generate random k1 in range [1, k)
        k1 = int.from_bytes(secrets.token_bytes(32), "little") % k if k > 1 else 0
        k2 = k - k1

        # For Ed25519, we work modulo L
        k1 = k1 % L
        k2 = k2 % L
    else:
        k1, k2 = split

    # Compute k1*P and k2*P separately
    P1 = scalar_multiply(k1, P)
    P2 = scalar_multiply(k2, P)

    # Add them together
    return point_add(P1, P2)


def point_equal(P1: EdwardsPoint, P2: EdwardsPoint) -> bool:
    """Check if two points are equal."""
    return P1.x == P2.x and P1.y == P2.y


def point_compress(P: EdwardsPoint) -> bytes:
    """Compress a point to 32 bytes.
    Format: 255 bits for y-coordinate (little-endian) + 1 sign bit for x.
    """
    y_bytes = P.y.to_bytes(32, "little")
    # Set the sign bit if x is negative (odd)
    if field_is_negative(P.x):
        y_bytes = y_bytes[:-1] + bytes([y_bytes[31] | 0x80])
    return y_bytes


def point_decompress(compressed: bytes) -> Optional[EdwardsPoint]:
    """Decompress a point from 32 bytes.
    Returns None if the bytes don't represent a valid curve point.
    """
    if len(compressed) != 32:
        return None

    # Extract y coordinate and sign bit
    y = int.from_bytes(compressed, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1  # Clear the sign bit

    # Check if y is in valid range
    if y >= P:
        return None

    # Recover x from the curve equation: x^2 = (y^2 - 1) / (d*y^2 + 1)
    y2 = field_square(y)
    numerator = field_sub(y2, 1)
    denominator = field_add(field_mul(D, y2), 1)

    if denominator == 0:
        return None

    x2 = field_mul(numerator, field_inv(denominator))

    # Compute square root
    x = field_sqrt(x2)
    if x is None:
        return None

    # Choose the correct sign
    if field_is_negative(x) != sign:
        x = field_neg(x)

    point = EdwardsPoint(x, y)

    # Verify the point is on the curve
    if not point.is_on_curve():
        return None

    return point


def is_small_order_point(P: EdwardsPoint) -> bool:
    """Check if a point has small order (1, 2, 4, or 8)."""
    # Check if 8*P = identity
    P8 = scalar_multiply(8, P)
    return P8.is_identity()


def point_has_small_order(compressed: bytes) -> bool:
    """Check if compressed point bytes represent a small order point."""
    point = point_decompress(compressed)
    if point is None:
        return False
    return is_small_order_point(point)
