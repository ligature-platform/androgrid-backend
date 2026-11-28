<#
.SYNOPSIS
    Canonical Turnkey Inbound Firewall Helper for AndroGrid Orchestrator.
.DESCRIPTION
    Configures scoped Windows Defender Firewall inbound rules for mobile worker
    control plane gRPC (50051) and mDNS discovery (5353 UDP).
    Requires explicit operator consent before applying changes.
    Enforces least privilege: scopes to Private profile and LocalSubnet by default.
    Web UI (8080) remains host-local loopback by default; for LAN access, use Caddy TLS proxy.
    Purges obsolete wildcard, broad, and plaintext rules during migration.
    Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001], Gate L-02
.PARAMETER Action
    Action to perform: 'Check', 'Preview', 'Apply', 'Configure', 'Remove'. Default is 'Check'.
.PARAMETER Profile
    Target Windows network connection profile: 'Private' (default), 'Domain', 'Public', or 'Any'.
.PARAMETER RemoteAddress
    Remote IP or subnet filter: 'LocalSubnet' (default) or custom CIDR / 'Any'.
.PARAMETER Unattended
    Executes in non-interactive mode without interactive confirmation prompts.
.PARAMETER Force
    Alias for -Unattended.
#>
[CmdletBinding()]
param (
    [ValidateSet("Check", "Preview", "Apply", "Configure", "Remove")]
    [string]$Action = "Check",

    [ValidateSet("Private", "Domain", "Public", "Any")]
    [string]$Profile = "Private",

    [string]$RemoteAddress = "LocalSubnet",

    [switch]$Unattended = $false,

    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

# Canonical AndroGrid firewall rule targets
$targetRules = @(
    @{
        Name        = "AndroGrid-gRPC-ControlPlane"
        DisplayName = "AndroGrid Control Plane gRPC"
        Protocol    = "TCP"
        Port        = 50051
        Description = "AndroGrid Control Plane gRPC Transport [REQ-OP-001]"
        Required    = $true
    },
    @{
        Name        = "AndroGrid-mDNS-Discovery"
        DisplayName = "AndroGrid Multicast DNS Discovery Responder"
        Protocol    = "UDP"
        Port        = 5353
        Description = "Multicast DNS Discovery Responder for Zero-Config Pairing [REQ-OP-001]"
        Required    = $true
    }
)

# Obsolete rules from legacy iterations to migrate/purge
$obsoleteRuleNames = @(
    "AndroGrid-Orchestrator-App",
    "AndroGrid-Artifact-HTTP",
    "AndroGrid-mDNS-Multicast",
    "AndroGrid-gRPC-50051",
    "AndroGrid-Artifacts-50052",
    "AndroGrid-WebUI-8080",
    "AndroGrid-mDNS-5353",
    "AndroGrid-Web-UI"
)

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Preview {
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "              AndroGrid Inbound Firewall Configuration Preview                  " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "Target Profile:         $Profile" -ForegroundColor Yellow
    Write-Host "Remote Address Scope:   $RemoteAddress" -ForegroundColor Yellow
    Write-Host "Web UI LAN Ingress:     DISABLED (Host-Local 127.0.0.1:8080 only; use Caddy for TLS proxy)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Inbound Rules to be Configured / Replaced:" -ForegroundColor Green
    foreach ($r in $targetRules) {
        Write-Host "  - [$($r.Protocol)] Port $($r.Port): $($r.DisplayName)" -ForegroundColor White
        Write-Host "      Name: $($r.Name) | Direction: Inbound | Action: Allow | Profile: $Profile | Scope: $RemoteAddress" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Obsolete / Broad Rules to be Purged:" -ForegroundColor Magenta
    foreach ($oldName in $obsoleteRuleNames) {
        $existing = Get-NetFirewallRule -Name $oldName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Host "  - [ACTIVE LEGACY] $oldName (Will be removed)" -ForegroundColor Red
        } else {
            Write-Host "  - [ABSENT] $oldName (Clean)" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "Active Network Connection Profiles:" -ForegroundColor Cyan
    $profiles = Get-NetConnectionProfile
    foreach ($p in $profiles) {
        $color = if ($p.NetworkCategory -eq "Private") { "Green" } else { "Yellow" }
        Write-Host "  Interface: $($p.InterfaceAlias) | Category: $($p.NetworkCategory) | IPv4: $($p.IPv4Connectivity)" -ForegroundColor $color
    }
    Write-Host "================================================================================" -ForegroundColor Cyan
}

switch ($Action) {
    "Preview" {
        Show-Preview
        exit 0
    }

    "Check" {
        Write-Host "[Audit] Checking existing AndroGrid firewall rules..." -ForegroundColor Cyan
        $allConfigured = $true

        foreach ($r in $targetRules) {
            $rule = Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            if ($rule) {
                $portFilter = $rule | Get-NetFirewallPortFilter
                $addressFilter = $rule | Get-NetFirewallAddressFilter
                $enabled = $rule.Enabled -eq "True"
                $ruleAction = $rule.Action
                $direction = $rule.Direction
                $ruleProfile = $rule.Profile

                $mismatches = @()
                if (-not $enabled) { $mismatches += "Enabled=$enabled" }
                if ($ruleAction -ne "Allow") { $mismatches += "Action=$ruleAction (expected Allow)" }
                if ($direction -ne "Inbound") { $mismatches += "Direction=$direction (expected Inbound)" }
                if ($portFilter.LocalPort -ne "$($r.Port)") { $mismatches += "Port=$($portFilter.LocalPort) (expected $($r.Port))" }
                if ($portFilter.Protocol -ne $r.Protocol) { $mismatches += "Protocol=$($portFilter.Protocol) (expected $($r.Protocol))" }
                if ($ruleProfile -ne $Profile) { $mismatches += "Profile=$ruleProfile (expected $Profile)" }
                if ($addressFilter.RemoteAddress -ne $RemoteAddress) { $mismatches += "RemoteAddress=$($addressFilter.RemoteAddress) (expected $RemoteAddress)" }

                $statusStr = if ($mismatches.Count -eq 0) { "ACTIVE" } else { "MISCONFIGURED" }
                $color = if ($statusStr -eq "ACTIVE") { "Green" } else { "Red" }

                Write-Host "  [$statusStr] $($r.DisplayName) ($($portFilter.Protocol) Port $($portFilter.LocalPort))" -ForegroundColor $color
                Write-Host "      Profile: $ruleProfile | RemoteAddress: $($addressFilter.RemoteAddress) | Enabled: $enabled" -ForegroundColor DarkGray
                if ($mismatches.Count -gt 0) {
                    Write-Host "      Mismatches: $($mismatches -join ', ')" -ForegroundColor Red
                    $allConfigured = $false
                }
            } else {
                Write-Host "  [MISSING] $($r.DisplayName) ($($r.Protocol) Port $($r.Port)): Not configured" -ForegroundColor Red
                $allConfigured = $false
            }
        }

        # Check for obsolete broad rules
        Write-Host ""
        Write-Host "[Audit] Checking for obsolete or overly broad legacy rules..." -ForegroundColor Cyan
        $foundObsolete = $false
        foreach ($oldName in $obsoleteRuleNames) {
            $existing = Get-NetFirewallRule -Name $oldName -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "  [WARNING] Legacy rule '$oldName' is still present. Run -Action Apply to purge." -ForegroundColor Yellow
                $foundObsolete = $true
            }
        }
        if (-not $foundObsolete) {
            Write-Host "  [OK] No obsolete wildcard application rules detected." -ForegroundColor Green
        }

        # Connection profile warning
        $profiles = Get-NetConnectionProfile
        $hasPublic = ($profiles | Where-Object { $_.NetworkCategory -eq "Public" }) -ne $null
        if ($hasPublic) {
            Write-Host ""
            Write-Host "  [NOTICE] One or more active network adapters are categorized as 'Public'." -ForegroundColor Yellow
            Write-Host "  Rules applied with -Profile Private will not permit ingress on Public adapters." -ForegroundColor Yellow
            Write-Host "  Ensure your Wi-Fi connection profile is set to 'Private' in Windows Settings." -ForegroundColor Yellow
        }

        if ($allConfigured -and -not $foundObsolete) {
            Write-Host ""
            Write-Host "Firewall audit PASSED: Inbound rules are properly installed and scoped." -ForegroundColor Green
            exit 0
        } else {
            Write-Host ""
            Write-Host "Firewall audit INCOMPLETE: Run .\setup-firewall.ps1 -Action Apply to configure." -ForegroundColor Yellow
            exit 2
        }
    }

    "Remove" {
        Show-Preview

        if (-not $Unattended -and -not $Force) {
            Write-Host ""
            $confirmation = Read-Host "Do you want to proceed with removing these AndroGrid firewall rules? [y/N]"
            if ($confirmation -notmatch "^[yY]([eE][sS])?$") {
                Write-Host "Operation cancelled by operator." -ForegroundColor Yellow
                exit 0
            }
        }

        if (-not (Test-IsAdmin)) {
            Write-Host "Administrative elevation required to remove firewall rules." -ForegroundColor Red
            Write-Host "Re-launching with elevation..." -ForegroundColor Yellow
            $proc = Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action Remove -Unattended" -PassThru -Wait
            exit $proc.ExitCode
        }

        Write-Host "[Tear Down] Removing all AndroGrid firewall rules..." -ForegroundColor Cyan
        foreach ($r in $targetRules) {
            Write-Host "  Deleting rule '$($r.Name)'..."
            Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
        }
        foreach ($oldName in $obsoleteRuleNames) {
            Write-Host "  Purging legacy rule '$oldName'..."
            Remove-NetFirewallRule -Name $oldName -ErrorAction SilentlyContinue
        }

        # Verify truthful absence of owned rules
        $remaining = @()
        foreach ($r in $targetRules) {
            $existing = Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            if ($existing) { $remaining += $r.Name }
        }
        if ($remaining.Count -gt 0) {
            Write-Host "Error: Failed to remove rules: $($remaining -join ', ')" -ForegroundColor Red
            exit 1
        }

        Write-Host "All AndroGrid firewall rules removed successfully." -ForegroundColor Green
        exit 0
    }

    { $_ -in "Apply", "Configure" } {
        Show-Preview

        # Informed consent check
        if (-not $Unattended -and -not $Force) {
            Write-Host ""
            $confirmation = Read-Host "Do you want to proceed with applying these firewall rule changes? [y/N]"
            if ($confirmation -notmatch "^[Yy]$") {
                Write-Host "Operation cancelled by operator. No firewall changes were applied." -ForegroundColor Yellow
                exit 0
            }
        }

        # Check elevation
        if (-not (Test-IsAdmin)) {
            Write-Host "Administrative elevation required to apply firewall changes." -ForegroundColor Yellow
            Write-Host "Requesting elevation..." -ForegroundColor Cyan
            $argsList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action Apply -Profile $Profile -RemoteAddress `"$RemoteAddress`" -Unattended"
            $proc = Start-Process powershell -Verb RunAs -ArgumentList $argsList -PassThru -Wait
            exit $proc.ExitCode
        }

        Write-Host ""
        Write-Host "[Configuration] Applying scoped AndroGrid firewall rules..." -ForegroundColor Cyan
        $hasErrors = $false

        # Step 1: Purge obsolete legacy rules
        foreach ($oldName in $obsoleteRuleNames) {
            try {
                Remove-NetFirewallRule -Name $oldName -ErrorAction SilentlyContinue
                Write-Host "  [PURGE] Removed obsolete legacy rule '$oldName'" -ForegroundColor DarkGray
            } catch {
                Write-Host "  [WARN] Failed to purge '$oldName': $_" -ForegroundColor Yellow
            }
        }

        # Step 2: Configure target rules
        foreach ($r in $targetRules) {
            try {
                # Delete existing instance if present
                Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue

                # Create scoped rule
                New-NetFirewallRule `
                    -Name $r.Name `
                    -DisplayName $r.DisplayName `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol $r.Protocol `
                    -LocalPort $r.Port `
                    -Profile $Profile `
                    -RemoteAddress $RemoteAddress `
                    -Description $r.Description `
                    -ErrorAction Stop | Out-Null

                Write-Host "  [OK] $($r.DisplayName) ($($r.Protocol) Port $($r.Port)) configured successfully." -ForegroundColor Green
            } catch {
                Write-Host "  [FAIL] Failed to configure $($r.DisplayName): $_" -ForegroundColor Red
                $hasErrors = $true
            }
        }

        Write-Host ""
        if (-not $hasErrors) {
            Write-Host "================================================================================" -ForegroundColor Green
            Write-Host "  Firewall configuration complete. Wireless LAN ingress is configured.           " -ForegroundColor Green
            Write-Host "================================================================================" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "  Firewall configuration encountered errors. Inspect error logs above.         " -ForegroundColor Red
            Write-Host "================================================================================" -ForegroundColor Red
            exit 1
        }
    }
}
