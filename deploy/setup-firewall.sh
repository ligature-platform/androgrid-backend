#!/usr/bin/env bash
#
# Canonical Turnkey Inbound Firewall Helper for AndroGrid Orchestrator (Linux).
#
# Detects active firewall tooling (ufw, firewalld, nftables, or iptables),
# previews rule mutations, requires explicit consent, and configures ingress
# for control plane gRPC (50051 TCP) and mDNS discovery (5353 UDP).
# Web UI (8080) remains host-local loopback by default; use Caddy for TLS LAN proxy.
#
# Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001], Gate L-02

set -euo pipefail

ACTION="${1:-check}"
SUBNET="${SUBNET:-}"
UNATTENDED="${UNATTENDED:-0}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --preview|preview) ACTION="preview"; shift ;;
        --check|check) ACTION="check"; shift ;;
        --apply|apply|configure) ACTION="apply"; shift ;;
        --remove|remove) ACTION="remove"; shift ;;
        --subnet)
            if [ -n "${2:-}" ]; then
                SUBNET="$2"
                shift 2
            else
                echo "Error: --subnet requires a CIDR argument (e.g., 192.168.1.0/24)" >&2
                exit 1
            fi
            ;;
        --subnet=*)
            SUBNET="${1#*=}"
            shift
            ;;
        -y|--unattended|--force) UNATTENDED=1; shift ;;
        *) shift ;;
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
    echo "Remote Subnet Filter:      ${SUBNET:-Any (Default LAN)}"
    echo "Web UI Ingress (Port 8080): DISABLED (Host-Local 127.0.0.1:8080 only; use Caddy for TLS proxy)"
    echo ""
    echo "Target Inbound Rules:"
    echo "  - [TCP] Port 50051 : AndroGrid Worker Control Plane gRPC [REQ-OP-001]"
    echo "  - [UDP] Port 5353  : Multicast DNS Discovery Responder [REQ-OP-001]"
    echo ""
    echo "Obsolete / Broad Rules to be Removed: (Port 8080 / legacy unauthenticated ingress)"
    echo "================================================================================"
}

case "$ACTION" in
    preview)
        show_preview
        exit 0
        ;;

    check)
        echo "[Audit] Checking existing firewall rules with manager: $MANAGER..."
        PASS=1
        case "$MANAGER" in
            ufw)
                if ! ufw status verbose | grep -E "50051.*ALLOW" >/dev/null; then
                    echo "  [MISSING] Port 50051/tcp not permitted in ufw."
                    PASS=0
                fi
                if ! ufw status verbose | grep -E "5353.*ALLOW" >/dev/null; then
                    echo "  [MISSING] Port 5353/udp not permitted in ufw."
                    PASS=0
                fi
                ;;
            firewalld)
                ZONE="$(firewall-cmd --get-default-zone 2>/dev/null || echo 'public')"
                PORTS="$(firewall-cmd --zone="$ZONE" --list-ports 2>/dev/null || true)"
                RICH="$(firewall-cmd --zone="$ZONE" --list-rich-rules 2>/dev/null || true)"
                if ! echo "$PORTS $RICH" | grep -q "50051"; then
                    echo "  [MISSING] Port 50051/tcp not found in firewalld zone $ZONE."
                    PASS=0
                fi
                if ! echo "$PORTS $RICH" | grep -q "5353"; then
                    echo "  [MISSING] Port 5353/udp not found in firewalld zone $ZONE."
                    PASS=0
                fi
                ;;
            iptables)
                RULES="$(iptables -L INPUT -n -v 2>/dev/null || true)"
                if ! echo "$RULES" | grep -E "50051" | grep -q "AndroGrid"; then
                    echo "  [MISSING] Port 50051 TCP rule with AndroGrid comment not found in iptables."
                    PASS=0
                fi
                if ! echo "$RULES" | grep -E "5353" | grep -q "AndroGrid"; then
                    echo "  [MISSING] Port 5353 UDP rule with AndroGrid comment not found in iptables."
                    PASS=0
                fi
                ;;
            nftables)
                echo "Error: nftables is active but automated rule management is not supported."
                exit 2
                ;;
            *)
                echo "No supported active firewall manager detected (ufw, firewalld, iptables)."
                echo "Ensure ports 50051 TCP and 5353 UDP are permitted on your host network interface."
                exit 2
                ;;
        esac

        if [ "$PASS" -eq 1 ]; then
            echo "Firewall audit PASSED: Inbound rules are properly configured."
            exit 0
        else
            echo "Firewall audit INCOMPLETE: Run ./setup-firewall.sh --apply to configure."
            exit 2
        fi
        ;;

    apply)
        show_preview

        if [ "$MANAGER" = "nftables" ]; then
            echo "Error: nftables is detected but automated rule management is not yet supported. Please configure nftables rules manually or use iptables-nft translation layer." >&2
            exit 1
        fi

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
                if [ -n "$SUBNET" ]; then
                    ufw allow from "$SUBNET" to any port 50051 proto tcp comment 'AndroGrid Control Plane gRPC'
                    ufw allow from "$SUBNET" to any port 5353 proto udp comment 'AndroGrid mDNS Responder'
                else
                    ufw allow 50051/tcp comment 'AndroGrid Control Plane gRPC'
                    ufw allow 5353/udp comment 'AndroGrid mDNS Responder'
                fi
                # Purge obsolete plaintext web UI if previously opened
                ufw delete allow 8080/tcp 2>/dev/null || true
                echo "[OK] ufw configuration updated."
                ;;
            firewalld)
                echo "Configuring firewalld rules..."
                if [ -n "$SUBNET" ]; then
                    firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$SUBNET' port port='50051' protocol='tcp' accept"
                    firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$SUBNET' port port='5353' protocol='udp' accept"
                else
                    firewall-cmd --permanent --add-port=50051/tcp
                    firewall-cmd --permanent --add-port=5353/udp
                fi
                firewall-cmd --permanent --remove-port=8080/tcp 2>/dev/null || true
                firewall-cmd --reload
                echo "[OK] firewalld configuration updated."
                ;;
            iptables)
                echo "Configuring iptables rules..."
                # Idempotently clean prior owned rules in a loop to avoid duplicate accumulation
                while iptables -D INPUT -p tcp --dport 50051 -m comment --comment "AndroGrid Control Plane gRPC" -j ACCEPT 2>/dev/null; do :; done
                while iptables -D INPUT -p udp --dport 5353 -m comment --comment "AndroGrid mDNS Responder" -j ACCEPT 2>/dev/null; do :; done
                if [ -n "$SUBNET" ]; then
                    while iptables -D INPUT -s "$SUBNET" -p tcp --dport 50051 -m comment --comment "AndroGrid Control Plane gRPC" -j ACCEPT 2>/dev/null; do :; done
                    while iptables -D INPUT -s "$SUBNET" -p udp --dport 5353 -m comment --comment "AndroGrid mDNS Responder" -j ACCEPT 2>/dev/null; do :; done
                fi

                if [ -n "$SUBNET" ]; then
                    iptables -A INPUT -s "$SUBNET" -p tcp --dport 50051 -m comment --comment "AndroGrid Control Plane gRPC" -j ACCEPT
                    iptables -A INPUT -s "$SUBNET" -p udp --dport 5353 -m comment --comment "AndroGrid mDNS Responder" -j ACCEPT
                else
                    iptables -A INPUT -p tcp --dport 50051 -m comment --comment "AndroGrid Control Plane gRPC" -j ACCEPT
                    iptables -A INPUT -p udp --dport 5353 -m comment --comment "AndroGrid mDNS Responder" -j ACCEPT
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
        show_preview

        if [ "$MANAGER" = "nftables" ]; then
            echo "Error: nftables is detected but automated rule management is not yet supported." >&2
            exit 1
        fi

        if [ "$UNATTENDED" -eq 0 ]; then
            read -r -p "Do you want to proceed with removing these AndroGrid firewall rules? [y/N]: " confirm
            case "$confirm" in
                [yY][eE][sS]|[yY]) ;;
                *) echo "Operation cancelled by operator."; exit 0 ;;
            esac
        fi

        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: Root privileges (sudo) required to remove Linux firewall rules." >&2
            exit 1
        fi

        case "$MANAGER" in
            ufw)
                echo "Removing ufw rules..."
                if [ -n "$SUBNET" ]; then
                    ufw delete allow from "$SUBNET" to any port 50051 proto tcp 2>/dev/null || true
                    ufw delete allow from "$SUBNET" to any port 5353 proto udp 2>/dev/null || true
                fi
                ufw delete allow 50051/tcp 2>/dev/null || true
                ufw delete allow 5353/udp 2>/dev/null || true
                ufw delete allow 8080/tcp 2>/dev/null || true
                ;;
            firewalld)
                echo "Removing firewalld rules..."
                if [ -n "$SUBNET" ]; then
                    firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$SUBNET' port port='50051' protocol='tcp' accept" 2>/dev/null || true
                    firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$SUBNET' port port='5353' protocol='udp' accept" 2>/dev/null || true
                fi
                firewall-cmd --permanent --remove-port=50051/tcp 2>/dev/null || true
                firewall-cmd --permanent --remove-port=5353/udp 2>/dev/null || true
                firewall-cmd --permanent --remove-port=8080/tcp 2>/dev/null || true
                firewall-cmd --reload
                ;;
            iptables)
                echo "Removing iptables rules..."
                while iptables -D INPUT -p tcp --dport 50051 -m comment --comment "AndroGrid Control Plane gRPC" -j ACCEPT 2>/dev/null; do :; done
                while iptables -D INPUT -p udp --dport 5353 -m comment --comment "AndroGrid mDNS Responder" -j ACCEPT 2>/dev/null; do :; done
                if [ -n "$SUBNET" ]; then
                    while iptables -D INPUT -s "$SUBNET" -p tcp --dport 50051 -m comment --comment "AndroGrid Control Plane gRPC" -j ACCEPT 2>/dev/null; do :; done
                    while iptables -D INPUT -s "$SUBNET" -p udp --dport 5353 -m comment --comment "AndroGrid mDNS Responder" -j ACCEPT 2>/dev/null; do :; done
                fi
                ;;
            *)
                echo "No active firewall manager found to remove rules from."
                ;;
        esac
        echo "[OK] Rules removed."
        exit 0
        ;;
esac
