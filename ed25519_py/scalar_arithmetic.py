"""Scalar arithmetic operations - redirects to unified arithmetic module."""

from .arithmetic import (
    clamp_scalar,
    is_canonical_scalar,
    scalar_add,
    scalar_from_bytes,
    scalar_inv,
    scalar_mul,
    scalar_reduce,
    scalar_sub,
    scalar_to_bytes,
)

__all__ = [
    "scalar_add",
    "scalar_sub",
    "scalar_mul",
    "scalar_inv",
    "scalar_reduce",
    "scalar_from_bytes",
    "scalar_to_bytes",
    "is_canonical_scalar",
    "clamp_scalar",
]
