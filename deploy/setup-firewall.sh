#!/usr/bin/env bash
#
# Canonical Turnkey Inbound Firewall Helper for AndroGrid Orchestrator (Linux).
#
# Detects active firewall tooling (ufw, firewalld, nftables, or iptables),
# previews rule mutations, requires explicit consent, and configures ingress
# for control plane gRPC (50051 TCP) and mDNS discovery (5353 UDP).
#
# Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001], Gate L-02

set -euo pipefail

ACTION="${1:-check}"
EXPOSE_WEB_UI="${EXPOSE_WEB_UI:-0}"
UNATTENDED="${UNATTENDED:-0}"

for arg in "$@"; do
    case "$arg" in
        --preview|preview) ACTION="preview" ;;
        --check|check) ACTION="check" ;;
        --apply|apply|configure) ACTION="apply" ;;
        --remove|remove) ACTION="remove" ;;
        --expose-web-ui) EXPOSE_WEB_UI=1 ;;
        -y|--unattended|--force) UNATTENDED=1 ;;
    esac
done

detect_manager() {
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        echo "ufw"
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        echo "firewalld"
    elif command -v nft >/dev/null 2>&1 && systemctl is-active --quiet nftables; then
        echo "nftables"
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}

MANAGER="$(detect_manager)"

show_preview() {
    echo "================================================================================"
    echo "              AndroGrid Inbound Firewall Configuration Preview (Linux)         "
    echo "================================================================================"
    echo "Detected Firewall Manager: $MANAGER"
    echo "Web UI Ingress (Port 8080): $([ "$EXPOSE_WEB_UI" -eq 1 ] && echo "ENABLED (LAN)" || echo "DISABLED (Host-Local Only)")"
    echo ""
    echo "Target Inbound Rules:"
    echo "  - [TCP] Port 50051 : AndroGrid Worker Control Plane gRPC [REQ-OP-001]"
    echo "  - [UDP] Port 5353  : Multicast DNS Discovery Responder [REQ-OP-001]"
    if [ "$EXPOSE_WEB_UI" -eq 1 ]; then
        echo "  - [TCP] Port 8080  : AndroGrid Operator Dashboard (LAN Ingress)"
    fi
    echo ""
    echo "Obsolete / Wildcard Rules to be Removed: (None / Purge application binaries)"
    echo "================================================================================"
}

case "$ACTION" in
    preview)
        show_preview
        exit 0
        ;;

    check)
        echo "[Audit] Checking existing firewall rules with manager: $MANAGER..."
        case "$MANAGER" in
            ufw)
                ufw status verbose | grep -E "50051|5353|8080" || echo "No AndroGrid specific rules active in ufw."
                ;;
            firewalld)
                firewall-cmd --list-ports | grep -E "50051|5353" || echo "Ports 50051/5353 not open in active firewalld zone."
                ;;
            iptables)
                iptables -L INPUT -n -v | grep -E "50051|5353" || echo "No iptables INPUT rules matching 50051/5353."
                ;;
            *)
                echo "No supported active firewall manager detected (ufw, firewalld, nftables, iptables)."
                echo "Ensure ports 50051 TCP and 5353 UDP are permitted on your host network interface."
                exit 0
                ;;
        esac
        exit 0
        ;;

    apply)
        show_preview

        if [ "$UNATTENDED" -eq 0 ]; then
            read -r -p "Do you want to proceed with applying these firewall rule changes? [y/N]: " confirm
            case "$confirm" in
                [yY][eE][sS]|[yY]) ;;
                *) echo "Operation cancelled by operator."; exit 0 ;;
            esac
        fi

        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: Root privileges (sudo) required to configure Linux firewall rules." >&2
            exit 1
        fi

        case "$MANAGER" in
            ufw)
                echo "Configuring ufw rules..."
                ufw allow 50051/tcp comment 'AndroGrid Control Plane gRPC'
                ufw allow 5353/udp comment 'AndroGrid mDNS Responder'
                if [ "$EXPOSE_WEB_UI" -eq 1 ]; then
                    ufw allow 8080/tcp comment 'AndroGrid Operator Dashboard'
                fi
                echo "[OK] ufw configuration updated."
                ;;
            firewalld)
                echo "Configuring firewalld rules..."
                firewall-cmd --permanent --add-port=50051/tcp
                firewall-cmd --permanent --add-port=5353/udp
                if [ "$EXPOSE_WEB_UI" -eq 1 ]; then
                    firewall-cmd --permanent --add-port=8080/tcp
                fi
                firewall-cmd --reload
                echo "[OK] firewalld configuration updated."
                ;;
            iptables)
                echo "Configuring iptables rules..."
                iptables -A INPUT -p tcp --dport 50051 -m comment --comment "AndroGrid Control Plane gRPC" -j ACCEPT
                iptables -A INPUT -p udp --dport 5353 -m comment --comment "AndroGrid mDNS Responder" -j ACCEPT
                if [ "$EXPOSE_WEB_UI" -eq 1 ]; then
                    iptables -A INPUT -p tcp --dport 8080 -m comment --comment "AndroGrid Operator Dashboard" -j ACCEPT
                fi
                echo "[OK] iptables rules inserted."
                ;;
            *)
                echo "Error: Cannot automatically configure firewall: no supported firewall manager active." >&2
                exit 1
                ;;
        esac
        exit 0
        ;;

    remove)
        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: Root privileges (sudo) required to remove Linux firewall rules." >&2
            exit 1
        fi

        case "$MANAGER" in
            ufw)
                echo "Removing ufw rules..."
                ufw delete allow 50051/tcp || true
                ufw delete allow 5353/udp || true
                ufw delete allow 8080/tcp || true
                ;;
            firewalld)
                echo "Removing firewalld rules..."
                firewall-cmd --permanent --remove-port=50051/tcp || true
                firewall-cmd --permanent --remove-port=5353/udp || true
                firewall-cmd --permanent --remove-port=8080/tcp || true
                firewall-cmd --reload
                ;;
            iptables)
                echo "Removing iptables rules..."
                iptables -D INPUT -p tcp --dport 50051 -j ACCEPT || true
                iptables -D INPUT -p udp --dport 5353 -j ACCEPT || true
                iptables -D INPUT -p tcp --dport 8080 -j ACCEPT || true
                ;;
            *)
                echo "No active firewall manager found to remove rules from."
                ;;
        esac
        echo "[OK] Rules removed."
        exit 0
        ;;
esac
