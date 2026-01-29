# SSH Scanner

A network scanner that identifies SSH hosts by their public key fingerprints, cross-referencing against known_hosts to detect IP changes.

## Installation

```bash
pip install -e .
```

Or with uv:
```bash
uv pip install -e .
```

## Usage

### Scan a network

```bash
sshscanner scan --network-prefix 192.168.1.0/24
```

With debug logging:
```bash
sshscanner scan --network-prefix 192.168.1.0/24 --debug
```

### Show report of last scan

```bash
sshscanner report
```

With custom known_hosts path:
```bash
sshscanner report --known-hosts-path ~/.ssh/known_hosts
```

### Manage hostname mappings

Add or update a hostname:
```bash
sshscanner name 10.12.1.80 ranos
```

Delete a hostname:
```bash
sshscanner name --del ranos
```

## Configuration

Configuration is stored in `~/.config/sshscan/config.yaml` and automatically created on first run:

```yaml
network_prefix: "192.168.1.0/24"
ssh_port: 22
timeout: 1.0
known_hosts_path: "~/.ssh/known_hosts"
```

## Database

Scan results and hostname mappings are stored in SQLite database at `~/.config/sshscan/scandb.sql`.

## License

MIT
