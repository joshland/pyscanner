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


def get_hostnames_by_fingerprint(fingerprint):
    """Get all hostnames associated with a fingerprint."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT hostname FROM hostnames WHERE fingerprint = ? ORDER BY timestamp DESC",
        (fingerprint,),
    )
    results = [row[0] for row in cursor.fetchall()]
    conn.close()
    return results


def get_last_scan_results():
    """Get the results of the most recent scan from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT MAX(timestamp) FROM scans")
    result = cursor.fetchone()
    if not result or not result[0]:
        conn.close()
        return None

    max_timestamp = result[0]

    cursor.execute(
        "SELECT DISTINCT ip, fingerprint FROM scans WHERE timestamp = ?",
        (max_timestamp,),
    )
    results = cursor.fetchall()
    conn.close()

    return results


def display_results(results, known_mapping=None):
    """Display scan results in the standard format."""
    print(
        f"\n{'[Host]':<18} | {'[Hostname]':<20} | {'[Past Addresses]':<30} | {'[Short SSH Fingerprint]'}"
    )
    print("-" * 110)

    for ip, fp in results:
        hostnames = get_hostnames_by_fingerprint(fp)
        hostname_str = ", ".join(hostnames) if hostnames else "Unknown"

        if known_mapping:
            past_entries = known_mapping.get(fp, [])
            others = [e for e in past_entries if e != ip]
            past_str = ", ".join(others) if others else "No history"
        else:
            past_str = "No history"

        short_fp = f"SHA256:{fp[:20]}..."

        print(f"{ip:<18} | {hostname_str:<20} | {past_str:<30} | {short_fp}")
        logger.debug(f"Host {ip}: hostname={hostname_str}, fingerprint={fp}")


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

    display_results(living_servers, known_mapping)


@app.command()
def report(
    known_hosts_path: Path = typer.Option(
        None,
        "--known-hosts-path",
        "-k",
        help="Path to known_hosts file",
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
):
    """Show the results of the last scan again."""

    logger.remove()
    if debug:
        logger.add(lambda msg: print(msg, end=""), level="DEBUG")
    else:
        logger.add(lambda msg: print(msg, end=""), level="INFO")

    config = load_config()
    known_hosts_path = Path(known_hosts_path or config.get("known_hosts_path"))
    known_hosts_path = known_hosts_path.expanduser()

    logger.debug(f"Using known_hosts path: {known_hosts_path}")

    known_mapping = parse_known_hosts(known_hosts_path)
    logger.debug(f"Loaded {len(known_mapping)} known host entries")

    init_db()

    results = get_last_scan_results()
    if not results:
        logger.info("No scan results found. Run a scan first.")
        raise typer.Exit(1)

    logger.debug(f"Retrieved {len(results)} results from last scan")

    display_results(results, known_mapping)


@app.command()
def name(
    last_scan_ip: str = typer.Argument(
        None, help="Last scan IP address (for add/update)"
    ),
    hostname: str = typer.Argument(None, help="Hostname to associate or delete"),
    del_hostname: str = typer.Option(None, "--del", "-D", help="Hostname to delete"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
):
    """Identify a hostname with an SSH fingerprint, or delete a hostname mapping."""

    logger.remove()
    if debug:
        logger.add(lambda msg: print(msg, end=""), level="DEBUG")
    else:
        logger.add(lambda msg: print(msg, end=""), level="INFO")

    init_db()

    if del_hostname:
        delete_hostname(del_hostname)
        return

    if not hostname or not last_scan_ip:
        logger.error("Both IP and hostname are required for add/update")
        logger.info("Usage: python scan.py name <ip> <hostname>")
        logger.info("Or: python scan.py name --del <hostname>")
        raise typer.Exit(1)

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


def delete_hostname(hostname: str):
    """Delete a hostname mapping from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT fingerprint FROM hostnames WHERE hostname = ?", (hostname,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        logger.error(f"Hostname '{hostname}' not found in database")
        raise typer.Exit(1)

    fingerprint = result[0]
    cursor.execute("DELETE FROM hostnames WHERE hostname = ?", (hostname,))
    deleted_count = cursor.rowcount

    conn.commit()
    conn.close()

    if deleted_count > 0:
        logger.info(f"Deleted hostname mapping: {hostname}")
        print(
            f"✓ Deleted hostname '{hostname}' (fingerprint: SHA256:{fingerprint[:20]}...)"
        )
    else:
        logger.warning(f"No hostname mapping found for '{hostname}'")


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
