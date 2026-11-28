# Turnkey Caddy Ingress for AndroGrid Operator Web UI

This directory provides a turnkey Caddy reverse-proxy configuration for operators who wish to access the AndroGrid Web UI Dashboard over local Wi-Fi / LAN with TLS 1.3 encryption and mandatory authentication.

Traces to: [INV-002], [NFR-SEC-001], Gate L-02

## Security Architecture

1. **Loopback Upstream Default:** By default, `androgrid-backend` binds its Operator Web UI to `127.0.0.1:8080` (loopback only). Port 8080 is not exposed in host firewalls.
2. **Encrypted Ingress:** Caddy terminates TLS on port 8443 using internal certificates (`tls internal`), enforcing TLS 1.3 to guarantee that tokens, pairing QR codes, and dashboard metrics are never transmitted in plaintext across the Wi-Fi network.
3. **Mandatory Whole-Route Authentication:** HTTP Basic Authentication (`basicauth`) is strictly enforced on all incoming Web UI routes (`/`, `/api/v1/*`, `/events`), preventing unauthenticated access from other LAN devices.

## Setup and Operation

### 1. Install Caddy

- Windows: `winget install CaddyServer.Caddy`
- Linux (Debian/Ubuntu):
  ```bash
  sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
  curl -1sLF 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLF 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
  sudo apt update
  sudo apt install caddy
  ```

### 2. Generate Operator Password Hash

Caddy requires bcrypt-hashed credentials for HTTP Basic Authentication. Generate a bcrypt hash for the `admin` operator:

```bash
caddy hash-password
# Enter password at the prompt, then copy the output string
```

Export the hash and optionally your LAN domain or IP:

```bash
# Linux / macOS
export ANDROGRID_ADMIN_HASH='<paste_bcrypt_hash_here>'
export ANDROGRID_DOMAIN='192.168.1.100' # Or your LAN hostname e.g. cluster.local

# Windows PowerShell
$env:ANDROGRID_ADMIN_HASH = '<paste_bcrypt_hash_here>'
$env:ANDROGRID_DOMAIN = '192.168.1.100' # Or your LAN hostname
```

### 3. Start Caddy Reverse Proxy

Run Caddy from this directory:

```bash
caddy run --config Caddyfile
```

### 4. Client Trust Configuration

Because Caddy uses an internal certificate authority for local development and LAN access, client browsers or curl clients may reject the self-signed CA by default.

- **To install Caddy CA on the server:**
  ```bash
  caddy trust
  ```
- **To trust Caddy CA on another LAN client machine:**
  Copy the root certificate from Caddy's data directory:
  - Windows: `%APPDATA%\Caddy\pki\authorities\local\root.crt`
  - Linux: `~/.local/share/caddy/pki/authorities/local/root.crt`
  Import `root.crt` into your browser or OS trusted root certification authorities store.
- **For diagnostic API access with curl:**
  ```bash
  curl -k -u admin:<your_password> https://192.168.1.100:8443/api/v1/cluster/status
  ```
