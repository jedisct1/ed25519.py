"""Unified arithmetic operations for Ed25519."""


from .constants import L, P


class FieldOps:
    """Field arithmetic operations modulo p = 2^255 - 19."""

    @staticmethod
    def add(a: int, b: int) -> int:
        return (a + b) % P

    @staticmethod
    def sub(a: int, b: int) -> int:
        return (a - b) % P

    @staticmethod
    def mul(a: int, b: int) -> int:
        return (a * b) % P

    @staticmethod
    def square(a: int) -> int:
        return (a * a) % P

    @staticmethod
    def pow(a: int, n: int) -> int:
        return pow(a, n, P)

    @staticmethod
    def inv(a: int) -> int:
        return pow(a, P - 2, P)

    @staticmethod
    def neg(a: int) -> int:
        return (P - a) % P

    @staticmethod
    def is_negative(a: int) -> bool:
        return a % 2 == 1

    @staticmethod
    def abs(a: int) -> int:
        a = a % P
        return P - a if FieldOps.is_negative(a) else a

    @staticmethod
    def reduce(a: int) -> int:
        return a % P

    @staticmethod
    def sqrt(a: int) -> int | None:
        if a == 0:
            return 0

        legendre = pow(a, (P - 1) // 2, P)
        if legendre == P - 1:
            return None

        x = pow(a, (P + 3) // 8, P)

        if (x * x) % P == a:
            return x

        x = (x * pow(2, (P - 1) // 4, P)) % P
        if (x * x) % P == a:
            return x

        return None

    @staticmethod
    def chi(a: int) -> int:
        r = pow(a, (P - 1) // 2, P)
        return -1 if r == P - 1 else r


class ScalarOps:
    """Scalar arithmetic operations modulo L (group order)."""

    @staticmethod
    def add(a: int, b: int) -> int:
        return (a + b) % L

    @staticmethod
    def sub(a: int, b: int) -> int:
        return (a - b) % L

    @staticmethod
    def mul(a: int, b: int) -> int:
        return (a * b) % L

    @staticmethod
    def inv(a: int) -> int:
        return pow(a, L - 2, L)

    @staticmethod
    def reduce(a: int) -> int:
        return a % L

    @staticmethod
    def from_bytes(s_bytes: bytes) -> int:
        return int.from_bytes(s_bytes, "little")

    @staticmethod
    def to_bytes(s: int) -> bytes:
        return (s % L).to_bytes(32, "little")

    @staticmethod
    def is_canonical(s_bytes: bytes) -> bool:
        if len(s_bytes) != 32:
            return False

        if s_bytes[31] & 0xF0 == 0:
            return True

        if s_bytes[31] & 0xE0 != 0:
            return False

        s = ScalarOps.from_bytes(s_bytes)
        return s < L

    @staticmethod
    def clamp(s_bytes: bytes) -> bytes:
        s = bytearray(s_bytes)
        s[0] &= 248
        s[31] &= 127
        s[31] |= 64
        return bytes(s)


# Compatibility aliases for easier migration
field_add = FieldOps.add
field_sub = FieldOps.sub
field_mul = FieldOps.mul
field_square = FieldOps.square
field_pow = FieldOps.pow
field_inv = FieldOps.inv
field_sqrt = FieldOps.sqrt
field_neg = FieldOps.neg
field_is_negative = FieldOps.is_negative
field_abs = FieldOps.abs
field_reduce = FieldOps.reduce
chi = FieldOps.chi

scalar_add = ScalarOps.add
scalar_sub = ScalarOps.sub
scalar_mul = ScalarOps.mul
scalar_inv = ScalarOps.inv
scalar_reduce = ScalarOps.reduce
scalar_from_bytes = ScalarOps.from_bytes
scalar_to_bytes = ScalarOps.to_bytes
is_canonical_scalar = ScalarOps.is_canonical
clamp_scalar = ScalarOps.clamp
