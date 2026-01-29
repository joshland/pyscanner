#!/usr/bin/env bash
set -euo pipefail

# --- Setup local Python development environment with uv ---

# Create virtual environment with uv
echo "Creating virtual environment with uv..."
uv venv

# Install dependencies
echo "Installing dependencies..."
uv pip install -r requirements.txt

# Add development tools
echo "Installing development tools..."
uv pip install pytest ruff black mypy

echo "✓ Development environment ready!"
echo ""
echo "To activate the environment:"
echo "  source .venv/bin/activate"
echo ""
echo "To run the scanner:"
echo "  python scan.py --network-prefix 192.168.1.0/24"
echo ""
echo "Example with debug logging:"
echo "  python scan.py --network-prefix 192.168.1.0/24 --debug"

ln -s .venv/bin/activate

