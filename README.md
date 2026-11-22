# NetPulse

**Discover. Connect. Share. Monitor.**

NetPulse is a local-first LAN dashboard for opted-in NetPulse devices. It provides account-protected dashboards, peer discovery, recipient-key-encrypted file transfers with recipient approval, encrypted local file storage, and operating-system resource/network telemetry.

## What it does (and does not do)

- UDP broadcast announces only the running NetPulse device; the service records private-address devices that also announce NetPulse. It does not scan address ranges or inspect packets.
- Peer trust is off by default. Compare the displayed SHA-256 public-key fingerprint with the device owner over a trusted channel before trusting a peer. If a peer key changes, trust is cleared.
- File contents are encrypted at rest with Fernet and peer copies use AES-256-GCM with the content key wrapped using the recipient's RSA-2048 public key. An incoming transfer remains encrypted and unavailable for download until the recipient accepts it.
- Accounts are local to each installation. The first registered account owns incoming transfers for that device. Passwords are scrypt-hashed and sessions use HTTP-only, SameSite cookies.
- Telemetry comes from `psutil` interface counters and local system APIs. No packet capture, remote-device monitoring, command execution, or external-network discovery is performed.

NetPulse is an initial LAN deployment, not a hardened public-internet service. Keep it on a trusted network, configure TLS for multi-device deployments, and protect the data directory and backups.

## Requirements

- Python 3.10 or newer (tested with Python 3.12)
- Windows, Linux, or macOS
- UDP broadcast allowed on the trusted LAN for automatic peer discovery
- TCP access to the configured NetPulse port between participating devices

Package versions are pinned in `requirements.txt`. The dashboard works without the Socket.IO CDN by falling back to API polling; the CDN enables lower-latency live updates.

## Install and run

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env and set NETPULSE_SECRET_KEY to a unique random value.
python app.py
```

Open `http://localhost:5000`. The app creates its SQLite database and device keys in `data\` on first run. For LAN access, allow TCP 5000 and UDP 37020 through the host firewall only on the trusted private network. Example elevated PowerShell rules:

```powershell
New-NetFirewallRule -DisplayName "NetPulse web (Private)" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "NetPulse discovery (Private)" -Direction Inbound -Protocol UDP -LocalPort 37020 -Action Allow -Profile Private
```

### Linux and macOS

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set NETPULSE_SECRET_KEY to a unique random value.
python app.py
```

Open `http://localhost:5000`. Permit inbound TCP 5000 and UDP 37020 only on the trusted LAN. Firewall commands vary by distribution and network policy.

### Secret generation

Generate a secret rather than using the example placeholder:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Use the equivalent command on macOS/Linux:

```sh
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Set the generated value as `NETPULSE_SECRET_KEY` in `.env`. When unset, NetPulse generates and stores an instance-specific secret under `data\.secret` / `data/.secret`. Never copy another instance's secret, Fernet key, or device private key to a second computer.

## Run on multiple LAN computers

1. Install and start NetPulse on each authorized device. Ensure each device can receive UDP broadcast on port 37020 and connect to the configured web port.
2. Sign in or create a local account on each instance. Use the actual host's LAN IP and configured public port to open its dashboard.
3. Wait for the other opted-in NetPulse devices to appear under **Network peers**.
4. Verify a peer's full fingerprint with its owner out of band, then select **Verify & trust**. Trust is local to the current NetPulse installation and is not shared across instances.
5. To send a file, choose the peer from **File sharing** and upload. The peer receives the encrypted transfer and must accept it under **Transfer history** before downloading/decryption.
6. To stop participating, set `NETPULSE_DISCOVERY=0` and restart the app, or stop NetPulse entirely.

Discovery advertises the host name, public-key fingerprint/material, and service port to the local broadcast domain. Do not enable it on networks you do not administer or trust. Discovery is IPv4 UDP broadcast and may be blocked by Wi-Fi client isolation, guest networks, VLAN boundaries, or host firewalls.

## Configuration

Copy `.env.example` to `.env`. Python-dotenv loads it at startup.

| Variable | Default | Description |
|---|---:|---|
| `NETPULSE_SECRET_KEY` | generated locally | Flask session signing secret |
| `NETPULSE_HOST` | `0.0.0.0` | Web server bind address |
| `NETPULSE_PORT` | `5000` | Local app server port |
| `NETPULSE_PUBLIC_PORT` | same as app port | Peer-advertised port (e.g. 443 behind a TLS proxy) |
| `NETPULSE_DATA_DIR` | `./data` | Database, keys, and encrypted files |
| `NETPULSE_MAX_FILE_SIZE` | `26214400` | Per-file limit in bytes (25 MiB) |
| `NETPULSE_MONITOR_INTERVAL` | `3` | Default telemetry interval in seconds |
| `NETPULSE_DISCOVERY` | `1` | Opt-in LAN peer discovery/broadcast |
| `NETPULSE_DISCOVERY_PORT` | `37020` | UDP discovery port |
| `NETPULSE_PUBLIC_SCHEME` | `http` | Scheme advertised to trusted peers |
| `NETPULSE_COOKIE_SECURE` | `0` | Set to `1` when HTTPS is terminated in front of NetPulse |
| `NETPULSE_TLS_CERT` / `NETPULSE_TLS_KEY` | unset | Optional PEM certificate and private key for direct HTTPS |

Users can choose a 2–30 second dashboard telemetry interval and dark/light appearance in **Settings & security**.

## HTTPS and deployment

For multi-device use beyond a trusted development LAN, put the app behind a TLS reverse proxy with a certificate trusted by all participating computers, or supply a trusted certificate and key directly with `NETPULSE_TLS_CERT` and `NETPULSE_TLS_KEY`. Configure a reverse proxy to forward WebSocket upgrades and normal HTTP, then set `NETPULSE_PUBLIC_SCHEME=https`, `NETPULSE_PUBLIC_PORT` to the externally reachable TLS port, and `NETPULSE_COOKIE_SECURE=1` on each instance. Direct TLS automatically sets secure session cookies and advertises HTTPS when no scheme override is configured. Use a production WSGI/WebSocket deployment server and a process manager; do not expose Flask's built-in development server directly to the internet. Ensure the certificate validates on every peer; do not disable certificate checks.

The peer file body is independently encrypted to the recipient device key, but TLS is still required to protect sessions, credentials, metadata, and the peer API in transit. Do not forward the discovery or web ports to the public internet.

## Storage and key management

`data/` contains the SQLite database, Fernet storage key, device RSA private key, Flask secret (when not configured externally), and encrypted file blobs. Keep the directory private and include it in protected backups if needed. The device private key and Fernet key are created with restrictive file permissions where supported; Windows administrators should additionally apply appropriate NTFS ACLs. Losing these keys makes existing encrypted files unreadable. Replacing a device's key also changes its peer fingerprint and requires peer trust to be re-established.

## Pages and API

The responsive dashboard includes Overview, Network peers, File sharing, Transfer history, Network analytics, System telemetry, and Settings & security. The JSON API is session-authenticated except for the peer-to-peer encrypted incoming-transfer endpoint, which accepts only a previously trusted peer's announced node ID and source address. Mutating browser requests require a session CSRF token.

Principal endpoints: `/api/auth/*`, `/api/dashboard`, `/api/peers`, `/api/transfers`, `/api/peer/transfers`, `/api/telemetry`, `/api/network`, `/api/telemetry/export.csv`, `/api/activity`, and `/api/settings`.

## Tests

```sh
python -m pytest -q
```

Tests cover app startup pages and APIs, registration/login, encrypted local storage, owner-only download, incoming trusted-peer transfer acceptance, and telemetry responses. LAN broadcast and multi-machine firewall behavior require testing on the target network.
