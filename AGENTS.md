# AGENTS.md

This file provides guidelines for agentic coding agents working in this repository.

## Project Overview

Python network scanner that identifies SSH hosts by their public key fingerprints, cross-referencing against known_hosts to detect IP changes. Uses SQLite database to store scan results and hostname mappings.

## Build/Lint/Test Commands

```bash
# Run the main script (scans network using config defaults)
python scan.py scan

# Scan with specific network prefix
python scan.py scan --network-prefix 192.168.1.0/24

# Scan with debug logging
python scan.py scan --network-prefix 192.168.1.0/24 --debug

# Show report of last scan
python scan.py report

# Name a host (identify hostname with fingerprint)
python scan.py name 10.12.1.80 ranos

# Delete a hostname mapping
python scan.py name --del ranos

# Install dependencies
pip install -r requirements.txt

# Lint (if tools are available)
ruff scan.py          # Fast Python linter (preferred)
flake8 scan.py        # Alternative linter
black scan.py         # Code formatter

# Run tests (if test framework exists)
pytest                # Run all tests
pytest -v             # Verbose output
pytest path/to/test.py  # Run specific test file
pytest -k "test_name" # Run tests matching pattern

# Type checking (if type hints added)
mypy scan.py
```

Note: This project currently has no formal test suite. When adding tests, use pytest.

## Output Format

Scan results and reports use the following column format:
- **[Host]**: Current IP address of the SSH host
- **[Hostname]**: Known hostname(s) associated with the SSH fingerprint (comma-separated)
- **[Past Addresses]**: Historical addresses from known_hosts file for this fingerprint
- **[Short SSH Fingerprint]**: First 20 characters of SHA256 fingerprint

Example:
```
[Host]             | [Hostname]           | [Past Addresses]               | [Short SSH Fingerprint]
--------------------------------------------------------------------------------------------------------------
192.168.1.10       | nas-server           | 10.0.1.50                      | SHA256:RNr98Lu4wmLwTu4hZ2ez...
192.168.1.20       | desktop              | No history                     | SHA256:AbCdEfGhIjKlMnOpQrSt...
```

## Configuration and Data Storage

### Config File
- Location: `~/.config/sshscan/config.yaml`
- Created automatically on first run with default values
- Contains: network_prefix, ssh_port, timeout, known_hosts_path
- Can be manually edited to change defaults

### Database
- Location: `~/.config/sshscan/scandb.sql`
- SQLite database with two tables:
  - `scans`: Stores scan results (ip, fingerprint, timestamp)
  - `hostnames`: Maps hostnames to fingerprints (hostname, fingerprint, last_ip, timestamp)
- Created automatically on first scan
- Used by name and report commands to resolve IPs to hostnames

### Database Schema

```sql
-- Scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Hostnames table
CREATE TABLE hostnames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    last_ip TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(hostname, fingerprint)
);
```

## Code Style Guidelines

### Imports
- Group imports: standard library first, then third-party packages, then local imports
- Sort alphabetically within each group
- One import per line preferred

```python
import os
import socket
from concurrent.futures import ThreadPoolExecutor

import paramiko
```

### Naming Conventions
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `NETWORK_PREFIX`, `SSH_PORT`)
- **Functions**: `snake_case` (e.g., `get_fingerprint`, `scan_host`)
- **Variables**: `snake_case` (e.g., `known_mapping`, `living_servers`)
- **Parameters**: Descriptive snake_case

### Formatting
- Use 4 spaces for indentation (no tabs)
- Follow PEP 8 guidelines
- Maximum line length: ~100 characters (code shows ~100 limit)
- Use f-strings for string formatting

### Docstrings
- Use triple-quoted docstrings for functions
- Format: Brief description, then detailed explanation
- Include return value documentation

```python
def parse_known_hosts():
    """
    Parses known_hosts and maps fingerprints to all associated hosts/IPs.
    Returns: { fingerprint: [list_of_known_names_or_ips] }
    """
```

### Error Handling
- Current pattern: Bare except with silent return on failure
- Prefer specific exceptions where possible
- Document expected exceptions in docstrings

```python
try:
    # operation
except Exception:
    return None  # Current pattern
```

### Constants and Configuration
- Define constants at module level with descriptive names
- Group configuration in dedicated section with header comment

```python
# --- Configuration ---
NETWORK_PREFIX = "192.168.1.0/24"
SSH_PORT = 22
TIMEOUT = 1.0
```

### Main Guard Pattern
- Always use `if __name__ == "__main__"` for script execution entry point
- Import runtime dependencies inside main when appropriate

```python
if __name__ == "__main__":
    main()
```

### Code Organization
- Group related functions together
- Use section headers with `# --- Section ---` format
- Data processing functions first, then execution logic

### Type Hints
- Not currently used in this codebase
- Consider adding for better IDE support and documentation
- Use Python 3.10+ style (no Optional[str], use str | None)

### Concurrency
- Use `concurrent.futures.ThreadPoolExecutor` for I/O-bound tasks
- Reasonable worker count for network operations (40 in current code)
- Always close connections/transports properly

### Security Considerations
- Timeout network connections to prevent hanging
- Parse untrusted data (like known_hosts) with proper libraries (paramiko)
- Never log or print sensitive data like private keys
