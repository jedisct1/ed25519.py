"""Console entry point for the complete Ed25519 test suite."""

from .comprehensive_test import run_comprehensive_tests
from .test_resistant_signing import run_all_tests as run_resistant_signing_tests
from .test_vectors import run_all_tests as run_vector_tests


def main() -> None:
    """Run all supported test suites."""
    run_vector_tests()
    run_comprehensive_tests()
    run_resistant_signing_tests()
