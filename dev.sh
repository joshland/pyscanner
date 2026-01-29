#!/usr/bin/env bash
set -euo pipefail

# --- Setup local Python development environment with uv ---

# Create virtual environment with uv
echo "Creating virtual environment with uv..."
uv venv

# Install dependencies
echo "Installing dependencies..."
uv pip install -r requirements.txt

# Install package in editable mode (creates sshscanner command)
echo "Installing package..."
uv pip install -e .

# Add development tools
echo "Installing development tools..."
uv pip install pytest ruff black mypy

echo "✓ Development environment ready!"
echo ""
echo "To activate the environment:"
echo "  source .venv/bin/activate"
echo ""
echo "To run the scanner using the installed command:"
echo "  sshscanner scan --network-prefix 192.168.1.0/24"
echo ""
echo "Or run directly with Python:"
echo "  python scan.py scan --network-prefix 192.168.1.0/24"
echo ""
echo "Example with debug logging:"
echo "  sshscanner scan --network-prefix 192.168.1.0/24 --debug"

ln -s .venv/bin/activate

