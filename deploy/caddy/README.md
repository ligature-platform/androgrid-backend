# Turnkey Caddy Ingress for AndroGrid Operator Web UI

This directory provides a turnkey Caddy reverse-proxy configuration for operators who wish to access the AndroGrid Web UI Dashboard over local Wi-Fi / LAN with TLS 1.3 encryption and authentication.

## Security Architecture

1. **Loopback Default:** By default, `androgrid-backend` binds its Operator Web UI to `127.0.0.1:8080` (loopback only). Port 8080 is not opened in host firewalls.
2. **Encrypted Ingress:** Caddy terminates TLS on port 8443 using internal certificates (`tls internal`), ensuring that tokens, QR codes, and dashboard metrics are never transmitted in plaintext across the Wi-Fi network.
3. **Authentication:** Operators can uncomment the `basicauth` block in `Caddyfile` to require credentials before accessing cluster management endpoints.

## Quick Start

1. Install Caddy (`winget install CaddyServer.Caddy` on Windows, or `sudo apt install caddy` on Linux).
2. Run Caddy from this directory:
   ```bash
   caddy run --config Caddyfile
   ```
3. Open `https://<host-lan-ip>:8443` in your browser.
