# Setup Guide — Home SOC Lab: Network Security & SIEM Implementation

**Author:** Jesus Gamez
**Wazuh Version:** 4.7.4
**Host OS:** Linux Mint
**Last Updated:** 2024

This guide documents the exact steps used to build this lab environment, including real issues encountered and their fixes. Follow these steps in order.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Install Docker Compose V2](#2-install-docker-compose-v2)
3. [Clone Wazuh Docker Repository](#3-clone-wazuh-docker-repository)
4. [Generate SSL Certificates](#4-generate-ssl-certificates)
5. [Start the Wazuh Stack](#5-start-the-wazuh-stack)
6. [Configure UFW Firewall Rules](#6-configure-ufw-firewall-rules)
7. [VirtualBox Network Configuration](#7-virtualbox-network-configuration)
8. [Deploy Wazuh Agent on Windows Server 2022](#8-deploy-wazuh-agent-on-windows-server-2022)
9. [Apply Custom Detection Rules](#9-apply-custom-detection-rules)
10. [Harden the Windows Server](#10-harden-the-windows-server)
11. [Run the Attack Simulation](#11-run-the-attack-simulation)
12. [Verify Detection in Wazuh Dashboard](#12-verify-detection-in-wazuh-dashboard)
13. [Troubleshooting Reference](#13-troubleshooting-reference)

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| Linux Mint (or Ubuntu-based host) | Tested on Linux Mint 21+ |
| 8 GB RAM minimum | 16 GB recommended; Wazuh indexer is memory-hungry |
| Docker Engine 24+ | Not Docker Desktop |
| Docker Compose V2 | **Not V1** — see Section 2 |
| VirtualBox 7.x | For running Windows Server and Kali VMs |
| Windows Server 2022 ISO | Evaluation available from Microsoft |
| Kali Linux ISO | From kali.org |
| Internet access | For pulling Docker images and Wazuh MSI |

---

## 2. Install Docker Compose V2

> **Why V2?** Docker Compose V1 (`docker-compose`) is written in Python and incompatible with Python 3.12 (installed by default on Linux Mint 22+). V2 is a Go binary and has no Python dependency.

### Remove V1 if present

```bash
# Check if V1 is installed
docker-compose --version

# Remove V1
sudo apt-get remove docker-compose -y
```

### Install V2 as a Docker CLI plugin

```bash
# Update package index
sudo apt-get update

# Install Docker and Compose V2 plugin together
sudo apt-get install -y docker.io docker-compose-plugin

# Verify — note: no hyphen in V2
docker compose version
# Expected: Docker Compose version v2.x.x
```

If Docker was previously installed, you may only need:

```bash
sudo apt-get install -y docker-compose-plugin
docker compose version
```

### Add your user to the docker group (avoid sudo on every command)

```bash
sudo usermod -aG docker $USER
newgrp docker
# Or log out and back in
```

---

## 3. Clone Wazuh Docker Repository

Wazuh provides an official Docker deployment repository with pre-configured compose files and certificate generators.

```bash
# Clone the Wazuh Docker repo at the correct version tag
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.4 --depth=1
cd wazuh-docker/single-node/

# Copy this repo's custom configs into place
cp /path/to/home-soc-lab/configs/local_rules.xml ./configs/
```

Alternatively, use the `docker-compose.yml` from this repository directly — it includes the custom rules volume mount.

---

## 4. Generate SSL Certificates

> **Critical Step:** The Wazuh Indexer (OpenSearch) requires TLS certificates to start. If you skip this or if it fails silently, the indexer container will crash with a cryptic TLS handshake error.

### Run the certificate generator

```bash
# From the single-node/ directory
docker compose -f generate-indexer-certs.yml run --rm generator
```

Expected output: a `config/wazuh_indexer_ssl_certs/` directory containing `.pem` and `.key` files.

### Verify certificate files were created correctly

```bash
ls -la config/wazuh_indexer_ssl_certs/
```

You should see files like:

```
admin-key.pem
admin.pem
root-ca-manager.pem
root-ca.pem
wazuh.dashboard-key.pem
wazuh.dashboard.pem
wazuh.indexer-key.pem
wazuh.indexer.pem
wazuh.manager-key.pem
wazuh.manager.pem
```

> **Known Bug — Directories Instead of Files:**
> If you see empty subdirectories instead of `.pem` files, a previous failed run created directories where Docker expected files. Fix:
>
> ```bash
> sudo rm -rf config/wazuh_indexer_ssl_certs/
> sudo rm -rf config/wazuh_dashboard_ssl_certs/
> docker compose -f generate-indexer-certs.yml run --rm generator
> ```
>
> See [Section 13 — Troubleshooting](#13-troubleshooting-reference) for full details.

---

## 5. Start the Wazuh Stack

```bash
# Start all three services (manager, indexer, dashboard) in detached mode
docker compose up -d

# Watch startup logs — wait for indexer to be ready before dashboard connects
docker compose logs -f wazuh.indexer
# Look for: "Wazuh app: Checking Wazuh API" — indicates startup is complete
```

### Verify all containers are running

```bash
docker compose ps
```

Expected output:
```
NAME                    STATUS
wazuh.manager           Up (healthy)
wazuh.indexer           Up (healthy)
wazuh.dashboard         Up (healthy)
```

### Access the Wazuh Dashboard

Open a browser and navigate to:

```
https://192.168.1.74
```

Accept the self-signed certificate warning.

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `SecretPassword` |

> **Tip:** Change the default password in a `.env` file before exposing the dashboard beyond localhost.

---

## 6. Configure UFW Firewall Rules

The Linux Mint host's firewall must allow the ports that Wazuh agents use to communicate with the manager.

```bash
# Allow Wazuh agent event forwarding (TCP and UDP)
sudo ufw allow 1514/tcp comment "Wazuh agent events TCP"
sudo ufw allow 1514/udp comment "Wazuh agent events UDP"

# Allow Wazuh agent enrollment/registration
sudo ufw allow 1515/tcp comment "Wazuh agent enrollment"

# Allow Wazuh REST API (used by Dashboard → Manager communication)
sudo ufw allow 55000/tcp comment "Wazuh REST API"

# Allow HTTPS for dashboard access (if accessing from other devices on LAN)
sudo ufw allow 443/tcp comment "Wazuh dashboard HTTPS"

# Verify rules are active
sudo ufw status verbose
```

> **Tip:** If you want to restrict these ports to your LAN only (more secure):
> ```bash
> sudo ufw allow from 192.168.1.0/24 to any port 1514 proto tcp
> sudo ufw allow from 192.168.1.0/24 to any port 1515 proto tcp
> sudo ufw allow from 192.168.1.0/24 to any port 55000 proto tcp
> ```

---

## 7. VirtualBox Network Configuration

### Understanding the Network Topology

Two VMs, two network adapters:

| VM | Adapter 1 | Purpose |
|---|---|---|
| Windows Server 2022 | Bridged → `wlp0s20f3` | Reach host (192.168.1.74) for Wazuh agent |
| Kali Linux | Internal Network (`homesoc`) | Isolated attack network |

Windows Server has a **second adapter** on the Internal Network (`homesoc`) to receive attack traffic from Kali.

### Configuring the Windows Server VM

1. Open VirtualBox → Select Windows Server 2022 → **Settings**
2. **Network → Adapter 1:**
   - Enable: ✓
   - Attached to: **Bridged Adapter**
   - Name: `wlp0s20f3` (your Wi-Fi interface — find yours with `ip link`)
3. **Network → Adapter 2:**
   - Enable: ✓
   - Attached to: **Internal Network**
   - Name: `homesoc`
4. Click OK

### Configuring the Kali Linux VM

1. Open VirtualBox → Select Kali Linux → **Settings**
2. **Network → Adapter 1:**
   - Enable: ✓
   - Attached to: **Internal Network**
   - Name: `homesoc`
3. Click OK

### Why Not Host-Only Networking?

Host-Only creates a separate subnet managed by VirtualBox that is isolated from the host's physical NIC. The VM gets an IP on the VirtualBox subnet (e.g., `192.168.56.x`) but **cannot reach the host's LAN IP** (`192.168.1.74`). This breaks Wazuh agent connectivity.

Bridged Adapter connects the VM directly to the physical network as if it were a physical machine — the VM gets a real DHCP IP on the same subnet as the host and can communicate directly.

### Verify Connectivity from Windows Server

Open a command prompt or PowerShell inside the Windows Server VM:

```powershell
# Test connectivity to the Wazuh manager (host machine)
ping 192.168.1.74

# Test the specific Wazuh ports
Test-NetConnection -ComputerName 192.168.1.74 -Port 1515  # enrollment
Test-NetConnection -ComputerName 192.168.1.74 -Port 1514  # events
```

Both should return `TcpTestSucceeded: True`.

---

## 8. Deploy Wazuh Agent on Windows Server 2022

> **Version Matching Requirement:** The Wazuh agent version **must exactly match** the manager version. For this lab: both must be `4.7.4`. A version mismatch causes silent connection failure — no error on the agent, nothing visible in manager logs.

### Automated Installation (Recommended)

Copy `scripts/setup-agent.ps1` to the Windows Server and run in an elevated PowerShell session:

```powershell
# Set execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Run the setup script
.\setup-agent.ps1
```

The script will:
1. Download `wazuh-agent-4.7.4-1.msi` from `packages.wazuh.com`
2. Install silently with `WAZUH_MANAGER=192.168.1.74`
3. Start the `WazuhSvc` service
4. Verify the service is running

### Manual Installation (Alternative)

If you prefer to install manually:

```powershell
# Download the exact version MSI
Invoke-WebRequest `
    -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.4-1.msi" `
    -OutFile "$env:TEMP\wazuh-agent-4.7.4-1.msi"

# Install silently
msiexec.exe /i "$env:TEMP\wazuh-agent-4.7.4-1.msi" `
    WAZUH_MANAGER="192.168.1.74" `
    WAZUH_AGENT_NAME="WindowsServer2022-Target" `
    /quiet /norestart

# Start the service
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic

# Verify
Get-Service WazuhSvc
```

### Confirm Agent is Active in Dashboard

1. Open `https://192.168.1.74` in a browser
2. Navigate to **Agents** in the left menu
3. Confirm your agent appears with status **Active**
4. Click the agent name → verify **Version: 4.7.4**

> **Agent shows Disconnected?** See [Troubleshooting — Version Mismatch](#agent-disconnected--version-mismatch).

---

## 9. Apply Custom Detection Rules

The custom Wazuh rules for RDP brute-force detection are in `configs/local_rules.xml`.

If you used the `docker-compose.yml` from this repo, the file is already mounted into the manager container via:

```yaml
- ./configs/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
```

To reload rules without restarting the manager:

```bash
docker exec -it wazuh-wazuh.manager-1 /var/ossec/bin/ossec-control reload
```

Verify the rules loaded successfully:

```bash
docker exec -it wazuh-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# Type a test event and check if rule 100002 matches
```

---

## 10. Harden the Windows Server

Run the hardening script on the Windows Server to enable audit logging and restrict RDP:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\harden-windows.ps1
```

This enables:
- Windows Firewall on all profiles
- Logon failure auditing (required for Event ID 4625 to appear)
- RDP restricted to the internal network subnet

> **Important:** Without enabling the audit policy for logon failures, Event ID 4625 will NOT be written to the Windows Security log, and Wazuh will not receive any brute-force events.

---

## 11. Run the Attack Simulation

From the **Kali Linux** VM (on the `homesoc` internal network):

```bash
# Identify the Windows Server IP on the internal network
# (Check ipconfig on Windows Server for the Internal Network adapter IP)

# Run Hydra RDP brute force
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://[WINDOWS_SERVER_INTERNAL_IP] -t 4 -V
```

Parameters:
- `-l Administrator` — target the Administrator account
- `-P rockyou.txt` — use the rockyou wordlist
- `-t 4` — 4 parallel tasks (avoid overloading RDP service)
- `-V` — verbose output

The attack should generate multiple Event ID 4625 entries on the Windows Server within seconds.

---

## 12. Verify Detection in Wazuh Dashboard

1. Open `https://192.168.1.74`
2. Navigate to **Security Events** (left menu)
3. Filter by your agent name
4. Look for:
   - **Rule ID 100001** — individual failed logon events
   - **Rule ID 100002** — brute force detected (Level 10 alert)
5. Click an alert to expand and view the full event details including source IP

### Respond to the Alert

Once the attacker IP is identified in the Wazuh alert, block it on the Windows Server:

```powershell
# On the Windows Server
.\configs\windows-firewall-block.ps1 -AttackerIP "[KALI_IP]"
```

---

## 13. Troubleshooting Reference

---

### Docker Compose V1 / Python 3.12 Error

**Symptom:**
```
AttributeError: module 'collections' has no attribute 'Callable'
```

**Fix:** Upgrade to Docker Compose V2 — see [Section 2](#2-install-docker-compose-v2).

---

### SSL Certificate Directories Instead of Files

**Symptom:** Indexer crashes on startup with TLS errors. `ls config/wazuh_indexer_ssl_certs/` shows directories, not `.pem` files.

**Fix:**
```bash
sudo rm -rf config/wazuh_indexer_ssl_certs/
sudo rm -rf config/wazuh_dashboard_ssl_certs/
docker compose -f generate-indexer-certs.yml run --rm generator
ls -la config/wazuh_indexer_ssl_certs/  # Verify .pem files exist
```

---

### Agent Disconnected / Version Mismatch

**Symptom:** Agent shows `Disconnected` in dashboard even though `WazuhSvc` is running on Windows Server. No errors visible anywhere.

**Fix:** Uninstall existing agent, then download the exact version:
```
https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.4-1.msi
```
Reinstall using `setup-agent.ps1`. Confirm version in dashboard matches manager.

---

### Agent Can't Reach Manager (Port 1514/1515)

**Symptom:** `Test-NetConnection -ComputerName 192.168.1.74 -Port 1514` returns `TcpTestSucceeded: False`.

**Possible causes:**
1. UFW blocking the port on the host → add UFW rules (Section 6)
2. VM using Host-Only instead of Bridged Adapter → switch to Bridged (Section 7)
3. Docker container not exposing the port → verify `docker compose ps` and port mappings

---

### Wazuh Dashboard Not Loading

**Symptom:** Browser shows connection refused or certificate error that can't be bypassed.

**Fix:**
```bash
# Check all containers are healthy
docker compose ps

# Restart in order if any are unhealthy
docker compose restart wazuh.indexer
# Wait 30 seconds
docker compose restart wazuh.manager
# Wait 15 seconds
docker compose restart wazuh.dashboard

# Check dashboard logs
docker compose logs wazuh.dashboard --tail 50
```

---

### No Event ID 4625 in Wazuh (Attack Running But No Alerts)

**Symptom:** Hydra is running, no alerts appear in Wazuh dashboard.

**Fix:** Verify audit policy is enabled on Windows Server:

```powershell
# Check current audit policy
auditpol /get /subcategory:"Logon"

# Should show: Logon  Success and Failure
# If it shows "No Auditing", run harden-windows.ps1 again
.\scripts\harden-windows.ps1
```

Also verify the Windows Security log is forwarded to Wazuh by checking `ossec.conf` includes the Security event channel localfile block.

---

*For additional help, consult the [Wazuh Documentation](https://documentation.wazuh.com/current/index.html).*
