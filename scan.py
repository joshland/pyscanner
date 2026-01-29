import os
import base64
import hashlib
import socket
import sqlite3
import yaml
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import paramiko
import typer
from loguru import logger

app = typer.Typer()

CONFIG_DIR = Path("~/.config/sshscan").expanduser()
DB_PATH = CONFIG_DIR / "scandb.sql"
CONFIG_PATH = CONFIG_DIR / "config.yaml"


def init_config():
    """Create default config if it doesn't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        default_config = {
            "network_prefix": "192.168.1.0/24",
            "ssh_port": 22,
            "timeout": 1.0,
            "known_hosts_path": "~/.ssh/known_hosts",
        }
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(default_config, f)
        logger.debug(f"Created default config at {CONFIG_PATH}")


def load_config():
    """Load configuration from yaml file."""
    init_config()
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def init_db():
    """Initialize SQLite database."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hostnames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            last_ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(hostname, fingerprint)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint ON scans(fingerprint)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_hostname_fp ON hostnames(hostname, fingerprint)"
    )
    conn.commit()
    conn.close()
    logger.debug(f"Database initialized at {DB_PATH}")


def save_scan_results(results):
    """Save scan results to database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    for ip, fp in results:
        cursor.execute(
            "INSERT INTO scans (ip, fingerprint, timestamp) VALUES (?, ?, ?)",
            (ip, fp, timestamp),
        )
    conn.commit()
    conn.close()
    logger.debug(f"Saved {len(results)} scan results to database")


def get_last_scan_ip(hostname):
    """Get the last IP associated with a hostname from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT last_ip FROM hostnames WHERE hostname = ? ORDER BY timestamp DESC LIMIT 1",
        (hostname,),
    )
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


def get_fingerprint_by_ip(ip):
    """Get the most recent fingerprint for an IP from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT fingerprint FROM scans WHERE ip = ? ORDER BY timestamp DESC LIMIT 1",
        (ip,),
    )
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


@app.command()
def scan(
    network_prefix: str = typer.Option(
        None,
        "--network-prefix",
        "-n",
        help="Network prefix to scan (e.g., 192.168.1.0/24)",
    ),
    ssh_port: int = typer.Option(None, "--ssh-port", "-p", help="SSH port to scan"),
    timeout: float = typer.Option(
        None, "--timeout", "-t", help="Connection timeout in seconds"
    ),
    known_hosts_path: Path = typer.Option(
        None,
        "--known-hosts-path",
        "-k",
        help="Path to known_hosts file",
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
):
    """Scan a network for SSH hosts and identify them by their public key fingerprints."""

    logger.remove()
    if debug:
        logger.add(lambda msg: print(msg, end=""), level="DEBUG")
    else:
        logger.add(lambda msg: print(msg, end=""), level="INFO")

    config = load_config()

    network_prefix = network_prefix or config.get("network_prefix")
    ssh_port = ssh_port if ssh_port is not None else config.get("ssh_port")
    timeout = timeout if timeout is not None else config.get("timeout")
    known_hosts_path = Path(known_hosts_path or config.get("known_hosts_path"))
    known_hosts_path = known_hosts_path.expanduser()

    logger.debug(
        f"Configuration: network_prefix={network_prefix}, ssh_port={ssh_port}, timeout={timeout}, known_hosts_path={known_hosts_path}"
    )

    logger.info(f"[*] Loading known_hosts and scanning {network_prefix}...")

    known_mapping = parse_known_hosts(known_hosts_path)
    logger.debug(f"Loaded {len(known_mapping)} known host entries")

    import ipaddress

    net = ipaddress.ip_network(network_prefix)
    logger.debug(
        f"Network has {list(net.hosts()) and len(list(net.hosts())) or 0} hosts to scan"
    )

    with ThreadPoolExecutor(max_workers=40) as executor:
        results = list(
            executor.map(lambda ip: scan_host(ip, ssh_port, timeout), net.hosts())
        )

    living_servers = [r for r in results if r]
    logger.debug(f"Found {len(living_servers)} active SSH hosts")

    init_db()
    save_scan_results(living_servers)

    print(
        f"\n{'[Host]':<18} | {'[Short Fingerprint]':<25} | {'[Past IP Addresses/Aliases]'}"
    )
    print("-" * 100)

    for current_ip, fp in living_servers:
        past_entries = known_mapping.get(fp, ["No history found"])
        others = [e for e in past_entries if e != current_ip]
        past_str = ", ".join(others) if others else "New (Not in known_hosts)"

        short_fp = f"SHA256:{fp[:20]}..."

        print(f"{current_ip:<18} | {short_fp:<25} | {past_str}")
        logger.debug(f"Host {current_ip}: fingerprint={fp}, history={past_str}")


@app.command()
def name(
    last_scan_ip: str = typer.Argument(..., help="Last scan IP address"),
    hostname: str = typer.Argument(..., help="Hostname to associate"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
):
    """Identify a hostname with an SSH fingerprint."""

    logger.remove()
    if debug:
        logger.add(lambda msg: print(msg, end=""), level="DEBUG")
    else:
        logger.add(lambda msg: print(msg, end=""), level="INFO")

    init_db()

    fingerprint = get_fingerprint_by_ip(last_scan_ip)
    if not fingerprint:
        logger.error(f"No fingerprint found for IP {last_scan_ip} in database")
        logger.info("Run a scan first to populate the database")
        raise typer.Exit(1)

    logger.debug(f"Found fingerprint {fingerprint} for IP {last_scan_ip}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM hostnames WHERE hostname = ? AND fingerprint = ?",
        (hostname, fingerprint),
    )
    existing = cursor.fetchone()

    if existing:
        cursor.execute(
            "UPDATE hostnames SET last_ip = ?, timestamp = ? WHERE id = ?",
            (last_scan_ip, datetime.now().isoformat(), existing[0]),
        )
        logger.info(f"Updated hostname mapping: {hostname} -> {fingerprint}")
    else:
        cursor.execute(
            "INSERT INTO hostnames (hostname, fingerprint, last_ip, timestamp) VALUES (?, ?, ?, ?)",
            (hostname, fingerprint, last_scan_ip, datetime.now().isoformat()),
        )
        logger.info(f"Added hostname mapping: {hostname} -> {fingerprint}")

    conn.commit()
    conn.close()

    print(
        f"✓ Hostname '{hostname}' associated with fingerprint SHA256:{fingerprint[:20]}..."
    )
    print(f"  Last IP: {last_scan_ip}")


def get_fingerprint(key):
    """Generates a SHA256 fingerprint from a paramiko PKey object."""
    fp_plain = hashlib.sha256(key.asbytes()).digest()
    return base64.b64encode(fp_plain).decode("utf-8").rstrip("=")


def parse_known_hosts(known_hosts_path):
    """
    Parses known_hosts and maps fingerprints to all associated hosts/IPs.
    Returns: { fingerprint: [list_of_known_names_or_ips] }
    """
    mapping = {}
    if not os.path.exists(known_hosts_path):
        logger.warning(f"Known hosts file not found: {known_hosts_path}")
        return mapping

    logger.debug(f"Parsing known_hosts file: {known_hosts_path}")
    host_keys = paramiko.HostKeys(known_hosts_path)

    for hostname, keys in host_keys.items():
        for key_type, key in keys.items():
            fp = get_fingerprint(key)
            if fp not in mapping:
                mapping[fp] = []
            if hostname not in mapping[fp]:
                mapping[fp].append(hostname)

    return mapping


def scan_host(ip, ssh_port, timeout):
    """Connects to host, grabs its public key, and returns (ip, fingerprint)."""
    target = str(ip)
    try:
        logger.debug(f"Scanning {target}:{ssh_port}")
        sock = socket.create_connection((target, ssh_port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.start_client()

        key = transport.get_remote_server_key()
        fp = get_fingerprint(key)
        logger.debug(f"Found SSH host {target} with fingerprint {fp}")

        transport.close()
        return (target, fp)
    except Exception as e:
        logger.debug(f"Failed to scan {target}:{ssh_port}: {e}")
        return None


if __name__ == "__main__":
    app()
