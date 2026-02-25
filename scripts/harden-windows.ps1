<#
.SYNOPSIS
    Hardens Windows Server 2022 for the Home SOC Lab environment.

.DESCRIPTION
    Applies a baseline security configuration aligned with common hardening
    practices for a monitored Windows endpoint in a home SOC environment:

      1. Enables Windows Firewall on all profiles (Domain, Private, Public)
      2. Restricts RDP access to the internal lab network only
      3. Enables audit logging for logon failures (Event ID 4625)
      4. Optionally blocks a specific attacker IP address

    This script is designed to be run AFTER installing the Wazuh agent
    (setup-agent.ps1) and BEFORE running attack simulations.

.PARAMETER AttackerIP
    Optional. If provided, creates a firewall rule to block this IP immediately.

.EXAMPLE
    # Run without blocking a specific IP
    .\harden-windows.ps1

.EXAMPLE
    # Run and immediately block the Kali Linux attacker VM
    .\harden-windows.ps1 -AttackerIP "10.0.2.15"

.NOTES
    Author:    Jesus Gamez
    Project:   Home SOC Lab — Network Security & SIEM Implementation
    Requires:  Administrator privileges
    Platform:  Windows Server 2022
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$AttackerIP
)

# ── Configuration ─────────────────────────────────────────────────────────────
# Internal lab network CIDR — adjust to match your VirtualBox Internal Network
# or the subnet used between Kali and Windows Server.
$INTERNAL_NETWORK = "10.0.2.0/24"    # VirtualBox Internal Network default
$LAN_NETWORK      = "192.168.1.0/24" # Bridged network (home LAN)
$RDP_PORT         = 3389

# ─────────────────────────────────────────────────────────────────────────────

# ── Privilege Check ───────────────────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  Windows Hardening Script — Home SOC Lab"     -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Enable Windows Firewall on All Profiles
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "[1/4] Enabling Windows Firewall on all profiles..." -ForegroundColor Yellow

# Three profiles cover all connectivity scenarios:
#   Domain  — when joined to an Active Directory domain
#   Private — trusted home/office networks
#   Public  — untrusted networks (guest Wi-Fi, etc.)
# Setting DefaultInboundAction to Block ensures any traffic not
# explicitly permitted by a rule is dropped by default.

try {
    Set-NetFirewallProfile -Profile Domain  -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Profile Public  -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

    Write-Host "[+] Firewall enabled on Domain, Private, and Public profiles." -ForegroundColor Green

    # Confirm current state
    $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
    $profiles | Format-Table -AutoSize
}
catch {
    Write-Error "[-] Failed to configure firewall profiles: $_"
    exit 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Restrict RDP Access to Internal Network Only
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "[2/4] Restricting RDP (TCP 3389) to internal network only..." -ForegroundColor Yellow

# Strategy:
#   a) Remove or disable the default "Remote Desktop" allow rules (too permissive)
#   b) Create a new rule allowing RDP only from the defined internal subnets
#
# This limits the attack surface: RDP is only reachable from the home LAN
# and the internal VirtualBox network, not from arbitrary external sources.

try {
    # Disable the built-in permissive RDP rules (allow from any source)
    $rdpRules = Get-NetFirewallRule -DisplayName "Remote Desktop*" -ErrorAction SilentlyContinue
    if ($rdpRules) {
        $rdpRules | Disable-NetFirewallRule
        Write-Host "    Disabled $($rdpRules.Count) default RDP allow rule(s)." -ForegroundColor Gray
    }

    # Create a scoped RDP allow rule limited to internal subnets
    $rdpRuleName = "SOC-LAB-RDP-Internal-Only"
    $existingScoped = Get-NetFirewallRule -DisplayName $rdpRuleName -ErrorAction SilentlyContinue

    if (-not $existingScoped) {
        New-NetFirewallRule `
            -DisplayName   $rdpRuleName `
            -Direction     Inbound `
            -Action        Allow `
            -Protocol      TCP `
            -LocalPort     $RDP_PORT `
            -RemoteAddress @($INTERNAL_NETWORK, $LAN_NETWORK) `
            -Profile       @("Domain", "Private", "Public") `
            -Enabled       True `
            -Description   "SOC Lab Hardening: Allow RDP only from internal lab subnets. Applied by harden-windows.ps1." `
            | Out-Null

        Write-Host "[+] RDP restricted to: $INTERNAL_NETWORK, $LAN_NETWORK" -ForegroundColor Green
    } else {
        Write-Host "[i] Scoped RDP rule '$rdpRuleName' already exists. Skipping." -ForegroundColor Gray
    }
}
catch {
    Write-Error "[-] Failed to configure RDP firewall rules: $_"
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Enable Audit Logging for Logon Failures (Event ID 4625)
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[3/4] Configuring audit policy for logon failure events..." -ForegroundColor Yellow

# Windows does not log failed logon attempts by default.
# Without this audit policy, Event ID 4625 will not appear in the Security log,
# and Wazuh cannot detect brute-force attempts.
#
# auditpol /set configures the Local Security Policy audit settings:
#   /subcategory:"Logon"  — the specific audit category
#   /failure:enable       — log failed logon attempts
#   /success:enable       — log successful logons (for correlation)

try {
    # Enable failure and success auditing for Logon events
    $auditResult = & auditpol /set /subcategory:"Logon" /failure:enable /success:enable 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "auditpol returned non-zero: $auditResult"
    } else {
        Write-Host "[+] Audit policy: Logon events — Failure: Enabled, Success: Enabled" -ForegroundColor Green
    }

    # Also enable Account Logon auditing (covers Kerberos/NTLM authentication)
    $auditResult2 = & auditpol /set /subcategory:"Credential Validation" /failure:enable /success:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Audit policy: Credential Validation — Failure: Enabled, Success: Enabled" -ForegroundColor Green
    }

    # Verify the setting was applied
    Write-Host "`n    Current audit policy (Logon):"
    & auditpol /get /subcategory:"Logon" | Where-Object { $_ -match "Logon" } | ForEach-Object {
        Write-Host "    $_" -ForegroundColor Gray
    }
}
catch {
    Write-Error "[-] Failed to configure audit policy: $_"
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Block Specific Attacker IP (Optional)
# ═══════════════════════════════════════════════════════════════════════════════
if ($AttackerIP) {
    Write-Host "`n[4/4] Blocking attacker IP: $AttackerIP..." -ForegroundColor Yellow

    $blockRuleName = "SOC-BLOCK-$AttackerIP"
    $existingBlock = Get-NetFirewallRule -DisplayName $blockRuleName -ErrorAction SilentlyContinue

    if (-not $existingBlock) {
        try {
            New-NetFirewallRule `
                -DisplayName   $blockRuleName `
                -Direction     Inbound `
                -Action        Block `
                -RemoteAddress $AttackerIP `
                -Protocol      Any `
                -Profile       @("Domain", "Private", "Public") `
                -Enabled       True `
                -Description   "SOC Lab: Blocked by harden-windows.ps1. IP: $AttackerIP. Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" `
                | Out-Null

            Write-Host "[+] Firewall rule created: Inbound traffic from $AttackerIP is BLOCKED." -ForegroundColor Green
        }
        catch {
            Write-Error "[-] Failed to create block rule for ${AttackerIP}: $_"
        }
    } else {
        Write-Host "[i] Block rule for $AttackerIP already exists. Skipping." -ForegroundColor Gray
    }
} else {
    Write-Host "`n[4/4] No attacker IP specified. Skipping IP block step." -ForegroundColor Gray
    Write-Host "      To block an IP later, run:"
    Write-Host "      .\windows-firewall-block.ps1 -AttackerIP `"<IP>`""
    Write-Host "      Or rerun this script:"
    Write-Host "      .\harden-windows.ps1 -AttackerIP `"<IP>`""
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  Hardening Complete" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Applied:"
Write-Host "  [+] Windows Firewall enabled on all profiles"
Write-Host "  [+] RDP restricted to internal network subnets"
Write-Host "  [+] Logon failure auditing enabled (Event ID 4625)"
if ($AttackerIP) {
    Write-Host "  [+] Attacker IP blocked: $AttackerIP"
}
Write-Host ""
Write-Host "  Verify in Wazuh dashboard:"
Write-Host "  - Security Events → filter by Rule ID 100001 or 100002"
Write-Host "  - Confirm Event ID 4625 alerts are flowing after an attack attempt"
Write-Host ""
