<#
.SYNOPSIS
    Blocks a specified attacker IP address in Windows Firewall.

.DESCRIPTION
    Standalone incident response script for blocking a known malicious IP.
    Creates an inbound firewall rule to drop all traffic from the attacker's
    IP address. Intended to be run manually after identifying a threat in the
    Wazuh SIEM dashboard.

    This script is intentionally verbose and commented for portfolio/learning
    purposes. Each step explains the reasoning behind the action taken.

.PARAMETER AttackerIP
    The IPv4 address to block. Required.

.EXAMPLE
    .\windows-firewall-block.ps1 -AttackerIP "10.0.2.15"

.NOTES
    Author:    Jesus Gamez
    Project:   Home SOC Lab — Network Security & SIEM Implementation
    Requires:  Administrator privileges (Run as Administrator)
    Reference: https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
#>

# ── Parameter Definition ────────────────────────────────────────────────────
# Accept the attacker's IP as a mandatory parameter.
# ValidatePattern enforces IPv4 format before execution proceeds.
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the attacker's IP address to block")]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$AttackerIP
)

# ── Privilege Check ──────────────────────────────────────────────────────────
# Firewall rule creation requires Administrator rights.
# Fail early with a clear message rather than a cryptic access-denied error.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell → 'Run as Administrator'."
    exit 1
}

# ── Timestamp & Logging Setup ────────────────────────────────────────────────
# All actions are logged to a flat file in C:\Logs\ for audit trail purposes.
# In a real SOC environment, this would ship to a centralized logging platform.
$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$logDir     = "C:\Logs\FirewallBlocks"
$logFile    = "$logDir\block-log.txt"
$ruleName   = "SOC-BLOCK-$AttackerIP"

# Create the log directory if it doesn't exist
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

Write-Host "`n[*] Home SOC Lab — Incident Response: IP Block Script" -ForegroundColor Cyan
Write-Host "[*] Timestamp : $timestamp"
Write-Host "[*] Target IP : $AttackerIP"
Write-Host "[*] Rule Name : $ruleName"
Write-Host "[*] Log File  : $logFile`n"

# ── Check for Duplicate Rule ─────────────────────────────────────────────────
# Prevent creating duplicate firewall rules if the IP was already blocked
# (e.g., during a previous incident response action or repeated script runs).
$existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

if ($existingRule) {
    Write-Warning "Firewall rule '$ruleName' already exists. IP $AttackerIP is already blocked."
    Write-Warning "To remove: Remove-NetFirewallRule -DisplayName '$ruleName'"
    exit 0
}

# ── Create the Inbound Block Rule ────────────────────────────────────────────
# New-NetFirewallRule parameters explained:
#
#   -DisplayName   : Human-readable name visible in Windows Firewall GUI
#   -Direction     : Inbound blocks traffic arriving FROM the attacker
#   -Action        : Block silently drops the packets (no RST sent)
#   -RemoteAddress : Restricts the rule to traffic from this specific IP
#   -Protocol      : Any = applies to TCP, UDP, and ICMP (full block)
#   -Profile       : Domain,Private,Public = active on all network profiles
#   -Enabled       : True = rule is immediately active upon creation
#   -Description   : Audit metadata — who blocked it, why, and when
#
Write-Host "[*] Creating inbound block rule in Windows Firewall..." -ForegroundColor Yellow

try {
    New-NetFirewallRule `
        -DisplayName   $ruleName `
        -Direction     Inbound `
        -Action        Block `
        -RemoteAddress $AttackerIP `
        -Protocol      Any `
        -Profile       @("Domain", "Private", "Public") `
        -Enabled       True `
        -Description   "SOC Incident Response: Blocked by windows-firewall-block.ps1 on $timestamp. Source: Wazuh alert — RDP brute-force (Rule ID 100002). Analyst: Home SOC Lab." `
        | Out-Null

    Write-Host "[+] SUCCESS: Inbound traffic from $AttackerIP is now blocked." -ForegroundColor Green
}
catch {
    Write-Error "[-] FAILED to create firewall rule: $_"
    Add-Content -Path $logFile -Value "[$timestamp] FAILED to block $AttackerIP — Error: $_"
    exit 1
}

# ── Verify the Rule Was Applied ──────────────────────────────────────────────
# Confirm the rule exists and is enabled before declaring success.
# This protects against silent failures in the firewall API.
Write-Host "`n[*] Verifying firewall rule..." -ForegroundColor Yellow

$verifyRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($verifyRule -and $verifyRule.Enabled -eq "True") {
    Write-Host "[+] Rule verified: '$ruleName' is active." -ForegroundColor Green
} else {
    Write-Warning "[-] Rule creation reported success but rule cannot be verified. Check Windows Firewall manually."
}

# ── Write Audit Log Entry ────────────────────────────────────────────────────
# Record the block action with timestamp for future review.
# Format: [timestamp] | ACTION | IP | RULE NAME | RESULT
$logEntry = "[$timestamp] | BLOCKED | IP: $AttackerIP | Rule: $ruleName | Status: Applied"
Add-Content -Path $logFile -Value $logEntry

Write-Host "`n[*] Audit entry written to: $logFile"
Write-Host "[*] Log entry: $logEntry"

# ── Next Steps Guidance ──────────────────────────────────────────────────────
Write-Host "`n[i] Next Steps:" -ForegroundColor Cyan
Write-Host "    1. Review Wazuh dashboard for continued alerts from $AttackerIP"
Write-Host "    2. Check Windows Security Event log for Event ID 4625 (should stop)"
Write-Host "    3. Document the incident in your SOC runbook"
Write-Host "    4. Consider adding $AttackerIP to perimeter firewall / router ACL"
Write-Host "    5. To remove this rule: Remove-NetFirewallRule -DisplayName '$ruleName'"
Write-Host ""
