<#
.SYNOPSIS
    Downloads and installs the Wazuh 4.7.4 agent on Windows Server 2022.

.DESCRIPTION
    Automates the Wazuh agent deployment process:
      1. Downloads the exact 4.7.4 MSI from packages.wazuh.com
      2. Installs silently with the correct manager IP
      3. Starts the WazuhSvc service
      4. Verifies the service is running

    IMPORTANT: Agent version must exactly match the manager version (4.7.4).
    A version mismatch causes silent connection refusal with no error message.
    See: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html

.NOTES
    Author:    Jesus Gamez
    Project:   Home SOC Lab — Network Security & SIEM Implementation
    Requires:  Administrator privileges, internet access on first run
    Platform:  Windows Server 2022
#>

# ── Configuration ─────────────────────────────────────────────────────────────
# Update MANAGER_IP to match your Wazuh manager's IP address.
# This is the host machine's IP where Docker is running Wazuh.
$MANAGER_IP      = "192.168.1.74"

# Wazuh agent version — must match the manager version exactly.
# Do NOT change this unless you have also updated the manager version.
$WAZUH_VERSION   = "4.7.4-1"
$AGENT_NAME      = "WindowsServer2022-Target"
$INSTALL_DIR     = "C:\Program Files (x86)\ossec-agent"

# Download URL — pulling directly from Wazuh's official package repository
$MSI_URL         = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION.msi"
$DOWNLOAD_PATH   = "$env:TEMP\wazuh-agent-$WAZUH_VERSION.msi"

# ─────────────────────────────────────────────────────────────────────────────

# ── Privilege Check ───────────────────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  Wazuh Agent Setup — Home SOC Lab"           -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Manager IP   : $MANAGER_IP"
Write-Host "  Agent Name   : $AGENT_NAME"
Write-Host "  Version      : $WAZUH_VERSION"
Write-Host "  MSI URL      : $MSI_URL"
Write-Host "================================================`n"

# ── Step 1: Check for Existing Installation ───────────────────────────────────
Write-Host "[1/5] Checking for existing Wazuh agent installation..." -ForegroundColor Yellow

$existingService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Warning "Existing WazuhSvc service detected."
    Write-Warning "If upgrading, uninstall the current agent via Add/Remove Programs first."
    Write-Warning "Version mismatch between agent and manager will cause silent disconnection."

    $response = Read-Host "Continue anyway? This may overwrite the existing installation. (y/N)"
    if ($response -notmatch '^[Yy]$') {
        Write-Host "Aborted by user." -ForegroundColor Red
        exit 0
    }
}

# ── Step 2: Download the MSI ──────────────────────────────────────────────────
Write-Host "`n[2/5] Downloading Wazuh agent $WAZUH_VERSION from official repository..." -ForegroundColor Yellow
Write-Host "      Source: $MSI_URL"
Write-Host "      Target: $DOWNLOAD_PATH"

try {
    # Use BitsTransfer for reliable large-file downloads with progress display.
    # Falls back to Invoke-WebRequest if BITS is unavailable.
    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        Start-BitsTransfer -Source $MSI_URL -Destination $DOWNLOAD_PATH -DisplayName "Wazuh Agent Download"
    } else {
        $progressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $MSI_URL -OutFile $DOWNLOAD_PATH -UseBasicParsing
    }

    if (-not (Test-Path $DOWNLOAD_PATH)) {
        throw "MSI file not found after download attempt."
    }

    $fileSize = (Get-Item $DOWNLOAD_PATH).Length / 1MB
    Write-Host "[+] Download complete. File size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Green
}
catch {
    Write-Error "[-] Download failed: $_"
    Write-Error "    Verify internet connectivity or download manually from:"
    Write-Error "    $MSI_URL"
    exit 1
}

# ── Step 3: Silent Installation ───────────────────────────────────────────────
Write-Host "`n[3/5] Installing Wazuh agent silently..." -ForegroundColor Yellow
Write-Host "      Manager IP: $MANAGER_IP"
Write-Host "      Agent Name: $AGENT_NAME"

# MSI properties passed during silent install:
#   WAZUH_MANAGER      — IP/hostname of the Wazuh manager
#   WAZUH_AGENT_NAME   — Display name shown in the Wazuh dashboard
#   WAZUH_REGISTRATION_SERVER — Manager IP for auto-enrollment via 1515/tcp
#   /quiet             — Suppress all UI dialogs
#   /norestart         — Do not auto-reboot (we control restart timing)
#   /log               — Write MSI install log for troubleshooting

$msiLog  = "$env:TEMP\wazuh-install.log"
$msiArgs = @(
    "/i", $DOWNLOAD_PATH,
    "WAZUH_MANAGER=$MANAGER_IP",
    "WAZUH_AGENT_NAME=$AGENT_NAME",
    "WAZUH_REGISTRATION_SERVER=$MANAGER_IP",
    "/quiet",
    "/norestart",
    "/log", $msiLog
)

try {
    $installProcess = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($installProcess.ExitCode -ne 0) {
        Write-Error "[-] MSI install failed with exit code: $($installProcess.ExitCode)"
        Write-Error "    Review install log: $msiLog"
        exit 1
    }
    Write-Host "[+] Installation complete. Exit code: $($installProcess.ExitCode)" -ForegroundColor Green
    Write-Host "    Install log saved to: $msiLog"
}
catch {
    Write-Error "[-] Unexpected error during installation: $_"
    exit 1
}

# ── Step 4: Start the WazuhSvc Service ───────────────────────────────────────
Write-Host "`n[4/5] Starting WazuhSvc service..." -ForegroundColor Yellow

try {
    # Set the service startup type to Automatic so it persists across reboots
    Set-Service -Name "WazuhSvc" -StartupType Automatic

    Start-Service -Name "WazuhSvc" -ErrorAction Stop
    Start-Sleep -Seconds 3  # Brief pause to allow service to fully initialize

    Write-Host "[+] WazuhSvc started successfully." -ForegroundColor Green
}
catch {
    Write-Error "[-] Failed to start WazuhSvc: $_"
    Write-Error "    Try manually: Start-Service WazuhSvc"
    Write-Error "    Check logs: $INSTALL_DIR\logs\ossec.log"
    exit 1
}

# ── Step 5: Verify Service Status ────────────────────────────────────────────
Write-Host "`n[5/5] Verifying service status..." -ForegroundColor Yellow

$service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

if ($service -and $service.Status -eq "Running") {
    Write-Host "[+] WazuhSvc is RUNNING." -ForegroundColor Green
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Agent setup complete!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Next steps:"
    Write-Host "  1. Open Wazuh Dashboard → Agents"
    Write-Host "     https://$MANAGER_IP (default: admin/SecretPassword)"
    Write-Host "  2. Confirm '$AGENT_NAME' shows status: Active"
    Write-Host "  3. Verify agent version matches manager (4.7.4)"
    Write-Host "  4. Run harden-windows.ps1 to apply security policies"
    Write-Host ""
} else {
    Write-Warning "WazuhSvc is NOT running. Status: $($service.Status)"
    Write-Warning "Troubleshooting:"
    Write-Warning "  - Check agent log: $INSTALL_DIR\logs\ossec.log"
    Write-Warning "  - Confirm manager is reachable: Test-NetConnection -ComputerName $MANAGER_IP -Port 1514"
    Write-Warning "  - Verify agent version matches manager: 4.7.4"
    exit 1
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Write-Host "[*] Cleaning up downloaded MSI..." -ForegroundColor Yellow
Remove-Item -Path $DOWNLOAD_PATH -Force -ErrorAction SilentlyContinue
Write-Host "[+] Done.`n" -ForegroundColor Green
