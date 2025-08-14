#!/bin/sh

echo "Running Black formatter..."
uv run black ed25519_py/

echo -e "\nRunning isort..."
uv run isort ed25519_py/

echo -e "\nRunning Ruff linter..."
uv run ruff check ed25519_py/ --fix --unsafe-fixes

echo -e "\nRunning MyPy type checker..."
uv run mypy ed25519_py/ --ignore-missing-imports

echo -e "\nRunning tests to ensure everything works..."
uv run python -m ed25519_py.test_vectors

echo -e "\n✅ Linting and formatting complete!"
