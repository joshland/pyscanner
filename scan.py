import socket
import os
import base64
import hashlib
import paramiko
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
NETWORK_PREFIX = "192.168.1.0/24"
SSH_PORT = 22
TIMEOUT = 1.0
KNOWN_HOSTS_PATH = os.path.expanduser("~/.ssh/known_hosts")

def get_fingerprint(key):
    """Generates a SHA256 fingerprint from a paramiko PKey object."""
    fp_plain = hashlib.sha256(key.asbytes()).digest()
    return base64.b64encode(fp_plain).decode('utf-8').rstrip('=')

def parse_known_hosts():
    """
    Parses known_hosts and maps fingerprints to all associated hosts/IPs.
    Returns: { fingerprint: [list_of_known_names_or_ips] }
    """
    mapping = {}
    if not os.path.exists(KNOWN_HOSTS_PATH):
        return mapping

    # Paramiko's HostKeys class helps us parse the file format
    host_keys = paramiko.HostKeys(KNOWN_HOSTS_PATH)
    
    for hostname, keys in host_keys.items():
        for key_type, key in keys.items():
            fp = get_fingerprint(key)
            if fp not in mapping:
                mapping[fp] = []
            if hostname not in mapping[fp]:
                mapping[fp].append(hostname)
    return mapping

def scan_host(ip):
    """Connects to host, grabs its public key, and returns (ip, fingerprint)."""
    target = str(ip)
    try:
        # Create a transport to grab the banner/key without a full login
        sock = socket.create_connection((target, SSH_PORT), timeout=TIMEOUT)
        transport = paramiko.Transport(sock)
        transport.start_client()
        
        key = transport.get_remote_server_key()
        fp = get_fingerprint(key)
        
        transport.close()
        return (target, fp)
    except Exception:
        return None

def main():
    import ipaddress
    print(f"[*] Loading known_hosts and scanning {NETWORK_PREFIX}...")
    
    known_mapping = parse_known_hosts()
    active_results = []

    net = ipaddress.ip_network(NETWORK_PREFIX)
    with ThreadPoolExecutor(max_workers=40) as executor:
        results = list(executor.map(scan_host, net.hosts()))

    # Filter for successful hits
    living_servers = [r for r in results if r]

    # Print Report
    print(f"\n{'[Host]':<18} | {'[Short Fingerprint]':<25} | {'[Past IP Addresses/Aliases]'}")
    print("-" * 100)

    for current_ip, fp in living_servers:
        # Get historical names associated with this specific key
        past_entries = known_mapping.get(fp, ["No history found"])
        # Clean up: remove the current IP from the 'past' list to avoid redundancy
        others = [e for e in past_entries if e != current_ip]
        past_str = ", ".join(others) if others else "New (Not in known_hosts)"
        
        # Display a shortened version of the fingerprint for readability
        short_fp = f"SHA256:{fp[:20]}..."
        
        print(f"{current_ip:<18} | {short_fp:<25} | {past_str}")

if __name__ == "__main__":
    main()
