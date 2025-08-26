"""
Official test vectors from "Taming the many EdDSAs" paper by Chalkias et al.
Source: https://github.com/novifinancial/ed25519-speccheck

These test vectors test edge cases in Ed25519 implementations.

IMPORTANT: The expected results here follow the STRICTEST security model (SUF-CMA + SBS)
as recommended by the paper for maximum security. This means:
- Rejecting all small order points (public keys and R components)
- Rejecting non-canonical encodings
- Rejecting signatures with torsion components in cofactorless mode
- Preventing all known malleability attacks

Some other implementations may accept certain signatures that we reject.
This is intentional - we choose security over compatibility.
"""

# Official test vectors from the paper (Table 6c)
# Format: (description, public_key, signature, message, expected_cofactored, expected_cofactorless)
PAPER_TEST_VECTORS_OFFICIAL = [
    # Test 1 - Small order public key with small order R (S=0)
    (
        "Small order public key with small order R (S=0)",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
        + "0000000000000000000000000000000000000000000000000000000000000000",
        "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        False,  # Should reject - small order public key
        False,  # Should reject - small order public key
    ),
    # Test 2 - Small order public key with mixed order R
    (
        "Small order public key with mixed order R",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"
        + "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        False,  # Should reject - small order public key
        False,  # Should reject - small order public key
    ),
    # Test 3 - Mixed order public key with small order R
    (
        "Mixed order public key with small order R",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
        + "8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        False,  # Should reject - small order R in cofactored
        False,  # Should also reject - small order R (STRICT SECURITY)
    ),
    # Test 4 - Valid signature with valid key
    (
        "Valid signature with valid key",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f"
        + "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        True,  # Should accept - valid signature
        True,  # Should accept - valid signature
    ),
    # Test 5 - Signature with torsion components (only valid with cofactored)
    (
        "Signature with torsion components",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512"
        + "5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        True,  # Should accept - valid with cofactored verification
        False,  # Should reject - contains torsion, fails cofactorless (STRICT SECURITY)
    ),
    # Test 6 - Signature with torsion (valid in cofactored only)
    (
        "Signature with torsion (valid in cofactored only)",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7"
        + "e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        True,  # Should accept - valid with cofactored verification
        False,  # Should reject - contains torsion components
    ),
    # Test 7 - Signature with non-canonical S (S > L)
    (
        "Signature with non-canonical S (S > L)",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e"
        + "547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        False,  # Should reject - S >= L (non-canonical)
        False,  # Should reject - S >= L (non-canonical)
    ),
    # Test 8 - Signature with S > L variant
    (
        "Signature with non-canonical S variant",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942"
        + "7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        False,  # Should reject - non-canonical S
        False,  # Should reject - non-canonical S
    ),
    # Test 9 - Small order R (ecff...ff is a small order point)
    (
        "Small order R (ecff...ff)",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        + "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        False,  # Should reject - R is small order (violates SUF-CMA)
        False,  # Should reject - R is small order (STRICT SECURITY)
    ),
    # Test 10 - Small order R (ecff...ff) with different S
    (
        "Small order R (ecff...ff) with different S",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        + "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        False,  # Should reject - R is small order
        False,  # Should also reject for security consistency
    ),
    # Test 11 - Small order public key (ecff...ff is a small order point)
    (
        "Small order public key (ecff...ff)",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
        + "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        False,  # Should reject - A is small order
        False,  # Should reject - A is small order
    ),
    # Test 12 - Small order public key with different message
    (
        "Small order public key (ecff...ff) variant",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
        + "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        False,  # Should reject - A is small order
        False,  # Should reject - A is small order
    ),
]
