"""Pure Python implementation of Ed25519 digital signatures.

This implementation follows the specification from "Taming the many EdDSAs"
and implements the most secure variant with SUF-CMA and SBS properties.
"""

from .key_generation import derive_public_key, generate_keypair
from .signing import sign, sign_resistant, sign_with_expanded_key_resistant
from .verification import batch_verify, verify, verify_cofactorless

__all__ = [
    "generate_keypair",
    "derive_public_key",
    "sign",
    "sign_resistant",
    "sign_with_expanded_key_resistant",
    "verify",
    "verify_cofactorless",
    "batch_verify",
]

__version__ = "1.0.0"
