#!/bin/bash
set -e

echo "Running all Ed25519 tests..."
echo

echo "=== RFC 8032 Test Vectors ==="
uv run python -m ed25519_py.test_vectors
echo

echo "=== Comprehensive Tests ==="
uv run python -m ed25519_py.comprehensive_test
echo

echo "=== Side-Channel Resistant Signing Tests ==="
uv run python -m ed25519_py.test_resistant_signing
echo

echo "=== Custom Test Vectors ==="
uv run python -m ed25519_py.test_custom_vector
echo

echo "=== Example Script ==="
uv run python -m ed25519_py.example
echo

echo "=== Package Test ==="
uv run python test_package.py
echo

echo "All tests completed successfully!"