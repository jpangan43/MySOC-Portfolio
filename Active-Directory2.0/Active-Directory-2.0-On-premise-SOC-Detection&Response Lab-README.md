# Active Directory 2.0 — SOC & Automated Incident Response Lab

## 📋 Table of Contents

1. [Lab Overview](#-lab-overview)
2. [Architecture](#-architecture)
3. [Prerequisites](#-prerequisites)
4. [Phase 1 — Infrastructure Setup](#phase-1--infrastructure-setup)
   - [Windows Server 2022](#11-windows-server-2022)
   - [Windows Client](#12-windows-client)
   - [Ubuntu Server](#13-ubuntu-server)
   - [Network Configuration](#14-network-configuration)
5. [Phase 2 — Active Directory Deployment](#phase-2--active-directory-deployment)
   - [Install Active Directory Domain Services](#21-install-active-directory-domain-services)
   - [Promote Server to Domain Controller](#22-promote-server-to-domain-controller)
   - [Create Organizational Units](#23-create-organizational-units)
   - [Create Domain Users](#24-create-domain-users)
   - [Configure Group Policy](#25-configure-group-policy)
   - [Join Windows Client to Domain](#26-join-windows-client-to-domain)
6. [Phase 3 — Windows Security Logging](#phase-3--windows-security-logging)
   - [Configure Advanced Audit Policy](#31-configure-advanced-audit-policy)
   - [Enable Logon Auditing](#32-enable-logon-auditing)
   - [Generate Test Security Events](#33-generate-test-security-events)
   - [Verify Windows Event Logs](#34-verify-windows-event-logs)
7. [Phase 4 — Splunk SIEM Deployment](#phase-4--splunk-siem-deployment)
   - [Install Splunk Enterprise](#41-install-splunk-enterprise)
   - [Install Splunk Universal Forwarder](#42-install-splunk-universal-forwarder)
   - [Configure Windows Log Collection](#43-configure-windows-log-collection)
   - [Verify Log Ingestion](#44-verify-log-ingestion)
   - [Create Detection Query](#45-create-detection-query)
   - [Create Splunk Alert](#46-create-splunk-alert)
8. [Phase 5 — Shuffle SOAR Deployment](#phase-5--shuffle-soar-deployment)
   - [Deploy Shuffle](#51-deploy-shuffle)
   - [Configure Shuffle](#52-configure-shuffle)
   - [Create Webhook](#53-create-webhook)
   - [Connect Splunk to Shuffle](#54-connect-splunk-to-shuffle)
9. [Phase 6 — SOAR Playbook Development](#phase-6--soar-playbook-development)
   - [Receive Splunk Alert](#61-receive-splunk-alert)
   - [Parse Alert Data](#62-parse-alert-data)
   - [Slack Notification](#63-slack-notification)
   - [Email Notification](#64-email-notification)
   - [Analyst Approval](#65-analyst-approval)
   - [Active Directory Response](#66-active-directory-response)
10. [Phase 7 — Attack Simulation & Testing](#phase-7--attack-simulation--testing)
11. [Phase 8 — Investigation & Analysis](#phase-8--investigation--analysis)
12. [Screenshots Index](#-screenshots-index)
13. [Detection Query Reference](#-detection-query-reference)
14. [Key Findings & Outcomes](#-key-findings--outcomes)
15. [Lessons Learned](#-lessons-learned)

---

# 📌 Lab Overview

This project demonstrates an on-premises Active Directory environment integrated with Splunk Enterprise and Shuffle SOAR to simulate a real-world SOC detection and automated incident response workflow.

The lab collects Windows security events, detects suspicious authentication activity, sends alerts to a SOC analyst, and uses Shuffle SOAR to automate the response after analyst approval.

### Objectives

- Deploy an on-premises Active Directory environment.
- Configure Windows Server 2022 as a Domain Controller.
- Join a Windows client to the domain.
- Configure Windows security auditing.
- Forward Windows security logs to Splunk.
- Create detection logic for suspicious authentication.
- Integrate Splunk with Shuffle SOAR.
- Automate Slack and email notifications.
- Implement analyst approval.
- Automatically disable a compromised Active Directory account.

---

# 🏗️ Architecture

The lab consists of a Windows Active Directory environment connected to a SIEM and SOAR platform.

```text
                         ┌─────────────────────┐
                         │   Windows Server    │
                         │   Domain Controller  │
                         │      (DC01)         │
                         └──────────┬──────────┘
                                    │
                                    │ Security Events
                                    │
                         ┌──────────▼──────────┐
                         │   Splunk Enterprise │
                         │        SIEM         │
                         └──────────┬──────────┘
                                    │
                                    │ Alert
                                    ▼
                         ┌─────────────────────┐
                         │    Shuffle SOAR     │
                         │     Playbook        │
                         └──────────┬──────────┘
                                    │
                     ┌──────────────┼──────────────┐
                     │              │              │
                     ▼              ▼              ▼
                  Slack          Email       SOC Analyst
                                                   │
                                                   ▼
                                         Analyst Approval
                                                   │
                                                   ▼
                                      Disable AD User Account
```

---

# 🔧 Prerequisites

## Hardware

| Component | Specification |
|---|---|
| CPU | 4+ cores |
| RAM | 16–32 GB |
| Storage | 150+ GB |
| Hypervisor | VMware Workstation |
| Network | Isolated/Internal Lab Network |

## Virtual Machines (VMware Workstation)

| VM | Role | Operating System |
|---|---|---|
| DC01 | Domain Controller | Windows Server 2022 |
| WIN11 | Domain Client | Windows 11 |
| Splunk | SIEM | Ubuntu Server |
| Shuffle | SOAR | Ubuntu Server |

> Update the VM names and specifications to match your actual lab environment.

---

# Phase 1 — Infrastructure Setup

## 1.1 Windows Server 2022

### Objective

Deploy Windows Server 2022 as the Domain Controller for the Active Directory environment.

### Procedure

1. Create a new virtual machine in VMware Workstation.
2. Assign the required CPU, RAM, and storage.
3. Attach the Windows Server 2022 ISO.
4. Boot the virtual machine.
5. Select the appropriate Windows Server 2022 edition.
6. Select **Desktop Experience**.
7. Complete the installation.
8. Configure the local Administrator password.
9. Log in to the server.
10. Rename the server to `DC01`.

```powershell
Rename-Computer -NewName "DC01"
Restart-Computer
```

11. Configure a static IP address.
12. Configure the Domain Controller as the preferred DNS server once AD DS is deployed.

### Verification

```powershell
hostname
ipconfig
```

### Expected Result

Windows Server 2022 is successfully deployed and prepared for Active Directory Domain Services.

---

## 1.2 Windows Client

### Objective

Deploy a Windows client that will be joined to the Active Directory domain.

### Procedure

1. Create a Windows 11 virtual machine in VMware Workstation.
2. Assign CPU, RAM, and storage.
3. Install Windows 11.
4. Configure the network adapter.
5. Configure the Domain Controller as the preferred DNS server.
6. Test connectivity to the Domain Controller.

```powershell
ping <DC01-IP>
```

7. Verify DNS resolution.

```powershell
nslookup <domain-name>
```

### Expected Result

The Windows client can communicate with the Domain Controller and resolve the Active Directory domain.

---

## 1.3 Ubuntu Server

### Objective

Prepare the Ubuntu Server used for the security monitoring and automation components.

### Procedure

```bash
sudo apt update
sudo apt upgrade -y
```

Configure the hostname:

```bash
sudo hostnamectl set-hostname splunk
```

Verify:

```bash
hostnamectl
ip addr
```

### Expected Result

The Ubuntu server is operational and ready for Splunk and/or Shuffle deployment.

---

## 1.4 Network Configuration

Configure the lab network so that all VMware virtual machines can communicate with each other.

Example:

```text
DC01       192.168.1.x
WIN11      192.168.1.x
Splunk     192.168.1.x
Shuffle    192.168.1.x
```

Replace the example addresses with your actual lab configuration.

### Verification

Test connectivity between the systems:

```powershell
ping <IP-address>
```

---

# Phase 2 — Active Directory Deployment

## 2.1 Install Active Directory Domain Services

Install AD DS using Server Manager or PowerShell.

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

Verify:

```powershell
Get-WindowsFeature AD-Domain-Services
```

### Expected Result

The Active Directory Domain Services role is installed successfully.

---

## 2.2 Promote Server to Domain Controller

1. Open **Server Manager**.
2. Select **AD DS**.
3. Select **Promote this server to a domain controller**.
4. Select **Add a new forest**.
5. Enter the lab domain name.

Example:

```text
mydfir.local
```

6. Configure DNS and Global Catalog.
7. Configure the Directory Services Restore Mode password.
8. Complete the prerequisite check.
9. Install.
10. Restart the server.

### Verification

```powershell
Get-ADDomain
Get-ADDomainController
```

### Expected Result

The Windows Server is functioning as the Active Directory Domain Controller.

---

## 2.3 Create Organizational Units

Open:

```text
Active Directory Users and Computers
```

Create the required organizational units.

Example:

```text
Users
Computers
Workstations
Servers
SOC
```

The OU structure should reflect the actual design of your lab.

---

## 2.4 Create Domain Users

Create test accounts that will be used during the SOC simulations.

Example:

```powershell
New-ADUser `
    -Name "TestUser" `
    -SamAccountName "TestUser" `
    -Enabled $true `
    -AccountPassword (Read-Host -AsSecureString)
```

Verify:

```powershell
Get-ADUser TestUser
```

---

## 2.5 Configure Group Policy

Open:

```text
Group Policy Management
```

Configure security auditing policies under:

```text
Computer Configuration
→ Policies
→ Windows Settings
→ Security Settings
→ Advanced Audit Policy Configuration
```

Configure relevant auditing categories such as:

- Account Logon
- Logon/Logoff
- Account Management
- Detailed Tracking

Apply the policy:

```powershell
gpupdate /force
```

Verify:

```powershell
gpresult /r
```

---

## 2.6 Join Windows Client to Domain

On the Windows 11 client:

1. Open **System Properties**.
2. Select **Change settings**.
3. Select **Change**.
4. Select **Domain**.
5. Enter the Active Directory domain.
6. Provide domain credentials.
7. Restart the client.

Verify:

```powershell
systeminfo | findstr /B /C:"Domain"
```

### Expected Result

The Windows client is successfully joined to the Active Directory domain.

---

# Phase 3 — Windows Security Logging

## 3.1 Configure Advanced Audit Policy

Configure the required auditing policies through Group Policy.

Recommended policies include:

```text
Audit Logon
Audit Account Logon
Audit Account Management
Audit Special Logon
```

Apply the configuration:

```powershell
gpupdate /force
```

---

## 3.2 Enable Logon Auditing

The lab focuses primarily on authentication activity.

Important Windows Security Event IDs include:

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credential logon |
| 4725 | User account disabled |
| 4726 | User account deleted |

For RDP authentication, Event ID **4624** with **Logon Type 10** is particularly useful.

---

## 3.3 Generate Test Security Events

Perform controlled authentication activity within the lab to generate Windows Security Events.

Examples include:

- Successful RDP authentication
- Failed authentication
- User logon
- User logoff

These events will later be collected and analyzed by Splunk.

---

## 3.4 Verify Windows Event Logs

Open:

```text
Event Viewer
→ Windows Logs
→ Security
```

Search for:

```text
4624
4625
```

For RDP activity, inspect:

```text
Logon Type: 10
```

### Expected Result

Windows is generating the security telemetry required for the SIEM detection stage.

---

# Phase 4 — Splunk SIEM Deployment

## 4.1 Install Splunk Enterprise

Install Splunk Enterprise on the designated Ubuntu server.

After installation, start Splunk and access the web interface:

```text
https://<Splunk-IP>:8000
```

Verify the Splunk service:

```bash
sudo systemctl status Splunkd
```

---

## 4.2 Install Splunk Universal Forwarder

Install the Splunk Universal Forwarder on the Windows system generating the security logs.

Verify the service:

```powershell
Get-Service SplunkForwarder
```

---

## 4.3 Configure Windows Log Collection

Configure the Universal Forwarder to collect Windows Event Logs.

Example:

```ini
[WinEventLog://Security]
disabled = 0
index = wineventlog
renderXml = true

[WinEventLog://System]
disabled = 0
index = wineventlog

[WinEventLog://Application]
disabled = 0
index = wineventlog
```

Restart:

```powershell
Restart-Service SplunkForwarder
```

---

## 4.4 Verify Log Ingestion

Search Splunk:

```spl
index=wineventlog
```

Successful logon:

```spl
index=wineventlog EventCode=4624
```

RDP authentication:

```spl
index=wineventlog EventCode=4624 Logon_Type=10
```

### Expected Result

Windows security events are successfully ingested into Splunk.

---

## 4.5 Create Detection Query

Create a detection for suspicious RDP authentication.

Example:

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| stats count by user, src_ip, ComputerName
```

Adapt the query to your actual lab environment and detection requirements.

---

## 4.6 Create Splunk Alert

Configure the detection search as an alert.

Example:

```text
Alert Name:
Suspicious RDP Login

Trigger:
When the search returns results

Action:
Send webhook to Shuffle
```

---

# Phase 5 — Shuffle SOAR Deployment

## 5.1 Deploy Shuffle

Deploy Shuffle on the designated Ubuntu server using Docker.

Verify the containers:

```bash
docker ps
```

---

## 5.2 Configure Shuffle

Access the Shuffle web interface and configure the workspace.

Verify that the Shuffle environment is operational.

---

## 5.3 Create Webhook

Create a webhook in Shuffle to receive alerts from Splunk.

Do **not** publish the real webhook URL in GitHub.

Use a placeholder:

```text
<SHUFFLE_WEBHOOK_URL>
```

---

## 5.4 Connect Splunk to Shuffle

Configure the Splunk alert to send its output to the Shuffle webhook.

Test the integration and verify that Shuffle receives the alert.

---

## 5.5 Troubleshooting Shuffle, Docker, and VMware Connectivity

During the Shuffle deployment and integration process, Docker networking, Shuffle worker connectivity, and communication with the on-premises VMware-hosted Active Directory environment were validated step by step.

> **Note:** The commands below document the troubleshooting procedure used in the lab. Replace placeholders such as `<container-name>`, `<network-name>`, `<vmware-vm-ip>`, and `<port>` with the values from your environment.

### Step 1 — Check Docker Service

Verify that Docker is running:

```bash
sudo systemctl status docker
```

If required, start and enable Docker:

```bash
sudo systemctl start docker
sudo systemctl enable docker
```

Verify the Docker installation:

```bash
docker version
```

### Step 2 — Check Shuffle Containers

List running containers:

```bash
sudo docker ps
```

List all containers, including stopped containers:

```bash
sudo docker ps -a
```

This was used to identify the Shuffle services and determine whether components such as Orborus were running, stopped, or restarting.

### Step 3 — Review Container Logs

When a Shuffle component failed to start or connect, its logs were reviewed:

```bash
sudo docker logs <container-name>
```

For live log monitoring:

```bash
sudo docker logs -f <container-name>
```

For the Shuffle worker/Orborus container, the logs were used to investigate startup, connection, and Docker networking errors.

### Step 4 — Check Docker Networks

List Docker networks:

```bash
sudo docker network ls
```

Inspect the network used by Shuffle:

```bash
sudo docker network inspect <network-name>
```

The inspection was used to verify the network driver, subnet, gateway, and containers connected to the network.

### Step 5 — Check the Shuffle Container IP

The IP address assigned to a Shuffle container was checked with:

```bash
sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container-name>
```

This helped verify that the container had valid network connectivity.

### Step 6 — Test Docker Host to VMware Connectivity

The Docker host was tested against the VMware-hosted Active Directory server:

```bash
ping <vmware-vm-ip>
```

TCP connectivity was also tested when required:

```bash
nc -zv <vmware-vm-ip> <port>
```

For HTTP-based services:

```bash
curl http://<vmware-vm-ip>:<port>
```

The objective was to confirm that the Docker host could reach systems on the VMware lab network.

### Step 7 — Verify VMware Windows VM Network Configuration

On the Windows virtual machines, network configuration was checked using:

```powershell
ipconfig /all
```

The following were reviewed:

- IPv4 address
- Subnet mask
- Default gateway
- DNS server

Connectivity to the Docker host was then tested from Windows:

```powershell
ping <docker-host-ip>
```

### Step 8 — Verify Routing

The Docker host routing table was reviewed:

```bash
ip route
```

Network interfaces were also checked:

```bash
ip addr
```

This helped verify that the Docker host had a route to the VMware lab subnet.

### Step 9 — Check Host Firewall

The host firewall was reviewed for possible blocked traffic:

```bash
sudo ufw status verbose
```

Only the ports required by the lab services should be permitted, and rules should be restricted to trusted lab networks where possible.

### Step 10 — Check Docker Swarm

Docker Swarm status was checked using:

```bash
sudo docker info
```

If Swarm had not been initialized, it was initialized with:

```bash
sudo docker swarm init
```

The Swarm node status was then verified:

```bash
sudo docker node ls
```

### Step 11 — Check Shuffle Orborus

The Orborus worker was specifically checked because it is responsible for executing Shuffle workflow actions.

```bash
sudo docker ps -a | grep -i orborus
```

The Orborus logs were reviewed:

```bash
sudo docker logs <orborus-container>
```

If the worker was stopped and the configuration was confirmed, it was restarted:

```bash
sudo docker restart <orborus-container>
```

The status was then checked again:

```bash
sudo docker ps
```

### Step 12 — Test Connectivity From the Shuffle Worker

A shell was opened inside the Shuffle worker container:

```bash
docker exec -it <shuffle-worker-container> sh
```

Connectivity to the Active Directory server was tested from inside the container.

LDAP:

```bash
nc -zv <active-directory-ip> 389
```

LDAPS:

```bash
nc -zv <active-directory-ip> 636
```

A successful test returned an `open` result, confirming that the Shuffle worker could reach the Active Directory service.

### Step 13 — Verify Active Directory From Windows

The Active Directory domain information was verified from the Windows server:

```powershell
(Get-ADDomain).DNSRoot
(Get-ADDomain).DistinguishedName
(Get-ADDomain).NetBIOSName
hostname
Get-Service NTDS
```

These checks confirmed the expected domain information and that Active Directory Domain Services was running.

### Step 14 — Test Active Directory User Lookup

The Shuffle Active Directory integration was first tested with a user lookup action before attempting account disablement.

The returned Distinguished Name was reviewed to confirm that Shuffle could successfully query Active Directory.

### Step 15 — Test a Safe Account Disablement

A dedicated lab test account was used to validate the response action instead of testing against a production account.

Example account:

```text
SAM account name: jsmith
```

The Shuffle Active Directory `disable_user` action was executed against the test account. A successful response confirmed that Shuffle could perform the account-disable operation.

### Step 16 — Configure Dynamic Username Mapping

The Active Directory `Disable user` action was configured to receive the username dynamically from the Splunk alert.

Example Shuffle expression:

```text
$exec.result.user
```

This allowed the workflow to pass the detected username into the Active Directory response action.

Example:

```text
Splunk detects: jsmith
        ↓
Shuffle receives: jsmith
        ↓
Active Directory disables: jsmith
```

### Step 17 — Final Connectivity Verification

After troubleshooting Docker, VMware, Orborus, and Active Directory connectivity, the complete workflow was tested again:

```text
Splunk Alert
      ↓
Shuffle Webhook
      ↓
Shuffle Workflow
      ↓
Orborus Worker
      ↓
Active Directory
      ↓
Disable User
```

The successful execution confirmed that the SOAR worker could communicate with the on-premises Active Directory environment and execute the required response action.

### Troubleshooting Command Reference

| Purpose | Command |
|---|---|
| Docker status | `sudo systemctl status docker` |
| Docker version | `docker version` |
| Running containers | `sudo docker ps` |
| All containers | `sudo docker ps -a` |
| Container logs | `sudo docker logs <container-name>` |
| Live logs | `sudo docker logs -f <container-name>` |
| Docker networks | `sudo docker network ls` |
| Inspect network | `sudo docker network inspect <network-name>` |
| Inspect container | `sudo docker inspect <container-name>` |
| Container IP | `sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container-name>` |
| Docker routing | `ip route` |
| Network interfaces | `ip addr` |
| Host firewall | `sudo ufw status verbose` |
| Swarm status | `sudo docker info` |
| Swarm nodes | `sudo docker node ls` |
| Initialize Swarm | `sudo docker swarm init` |
| Restart container | `sudo docker restart <container-name>` |
| Enter worker container | `docker exec -it <container-name> sh` |
| Test connectivity | `ping <ip>` |
| Test TCP port | `nc -zv <ip> <port>` |
| Windows network config | `ipconfig /all` |
| AD domain | `(Get-ADDomain)` |
| AD service | `Get-Service NTDS` |

---

# Phase 6 — SOAR Playbook Development

## 6.1 Receive Splunk Alert

Configure the Shuffle workflow to start when the Splunk webhook receives an alert.

The alert should contain relevant information such as:

```text
Username
Source IP
Computer
Event ID
Timestamp
Alert Name
```

---

## 6.2 Parse Alert Data

Extract the relevant information from the Splunk alert.

Example:

```text
User: TestUser
Computer: WIN11
Source IP: 192.168.1.x
Event ID: 4624
Logon Type: 10
```

---

## 6.3 Slack Notification

Configure Shuffle to notify the SOC analyst through Slack.

Example message:

```text
🚨 Suspicious RDP Login Detected

User: TestUser
Computer: WIN11
Source IP: 192.168.1.x
Event ID: 4624
Logon Type: 10

Analyst action required.
```

---

## 6.4 Email Notification

Configure an email notification containing the relevant incident information.

---

## 6.5 Analyst Approval

Implement a decision point in the playbook.

```text
Suspicious Login
       │
       ▼
Analyst Approval
     /     \
 Approve   Deny
    │        │
    ▼        ▼
Disable    No Action
 Account
```

This prevents an automated response from being executed without analyst review.

---

## 6.6 Active Directory Response

When the analyst approves the response, Shuffle triggers the Active Directory account disablement action.

Example:

```powershell
Disable-ADAccount -Identity "TestUser"
```

Verify:

```powershell
Get-ADUser TestUser -Properties Enabled
```

Expected:

```text
Enabled : False
```

> Never publish real credentials, API keys, webhook URLs, or secrets in the repository.

---

# Phase 7 — Attack Simulation & Testing

## 7.1 Simulate Suspicious RDP Login

Perform a controlled RDP authentication test using the lab environment.

Document:

```text
Source:
Destination:
Username:
Timestamp UTC:
Authentication Type:
```

---

## 7.2 Generate Security Event

Verify that the authentication generates:

```text
Event ID: 4624
Logon Type: 10
```

---

## 7.3 Validate Splunk Detection

Run:

```spl
index=wineventlog EventCode=4624 Logon_Type=10
```

Confirm that the test event is detected.

---

## 7.4 Validate Shuffle Automation

Confirm the complete workflow:

```text
Windows Event
      ↓
Splunk Detection
      ↓
Splunk Alert
      ↓
Shuffle Webhook
      ↓
Shuffle Playbook
      ↓
Slack + Email
      ↓
Analyst Approval
      ↓
AD Account Disablement
```

---

## 7.5 Validate Account Disablement

Verify the Active Directory account:

```powershell
Get-ADUser TestUser -Properties Enabled
```

Confirm that:

```text
Enabled : False
```

---

# Phase 8 — Investigation & Analysis

## 8.1 Review Security Events

Review relevant Windows Security Events:

```text
4624 — Successful Logon
4625 — Failed Logon
4634 — Logoff
4648 — Explicit Credential Logon
4725 — Account Disabled
```

Determine:

- Who logged in?
- From where?
- When?
- Which computer?
- What type of logon?

---

## 8.2 Investigate Source IP

Identify the source IP associated with the authentication.

Document:

```text
Source IP:
Username:
Hostname:
Timestamp UTC:
Logon Type:
```

---

## 8.3 Review User Activity

Search Splunk for additional activity associated with the account.

Example:

```spl
index=wineventlog user="TestUser"
```

Review:

- Successful logons
- Failed logons
- Remote access
- Account changes
- Other suspicious activity

---

## 8.4 Document Incident Findings

Example:

```markdown
### Incident Findings

Time: 2026-08-29 14:25:00 UTC
User: TestUser
Host: WIN11
Source IP: 192.168.1.x
Event ID: 4624
Logon Type: 10
Detection: Suspicious RDP Login
Response: Active Directory account disabled
```

---

# 📸 Screenshots Index

Screenshots are maintained separately in the `screenshots/` directory.

| # | Screenshot | Phase |
|---|---|---|
| 01 | Lab Architecture | Overview |
| 02 | Windows Server 2022 | Phase 1 |
| 03 | Windows Client | Phase 1 |
| 04 | Network Configuration | Phase 1 |
| 05 | AD DS Installation | Phase 2 |
| 06 | Domain Controller | Phase 2 |
| 07 | Active Directory Users & Computers | Phase 2 |
| 08 | Group Policy | Phase 2 |
| 09 | Windows Security Event | Phase 3 |
| 10 | Splunk Dashboard | Phase 4 |
| 11 | Splunk Detection | Phase 4 |
| 12 | Splunk Alert | Phase 4 |
| 13 | Shuffle Dashboard | Phase 5 |
| 14 | Shuffle Playbook | Phase 6 |
| 15 | Slack Notification | Phase 6 |
| 16 | Email Notification | Phase 6 |
| 17 | Analyst Approval | Phase 6 |
| 18 | Disabled AD Account | Phase 7 |
| 19 | Investigation Results | Phase 8 |

---

# 🔎 Detection Query Reference

Keep the actual Splunk queries used in the project here.

### Successful RDP Authentication

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| stats count by user, src_ip, ComputerName
```

### Failed Authentication

```spl
index=wineventlog EventCode=4625
| stats count by user, src_ip, ComputerName
```

### Disabled Account

```spl
index=wineventlog EventCode=4725
```

> Replace these examples with the final queries actually used in your lab.

---

# 🎯 Key Findings & Outcomes

- Built an on-premises Active Directory environment.
- Deployed Windows Server 2022 as a Domain Controller.
- Joined a Windows client to the Active Directory domain.
- Configured Windows security auditing and event collection.
- Forwarded Windows security telemetry to Splunk.
- Developed detection logic for suspicious authentication activity.
- Integrated Splunk with Shuffle SOAR.
- Automated Slack and email notifications.
- Implemented analyst approval before taking response actions.
- Successfully automated Active Directory account disablement.
- Demonstrated an end-to-end SOC detection and response workflow.

---

# 📚 Lessons Learned

### What I Learned

- Active Directory administration
- Windows Server administration
- Windows Security Event analysis
- Splunk SIEM configuration
- Detection engineering
- Shuffle SOAR automation
- SOC alert triage
- Incident response
- Security workflow automation

### Challenges

- Configuring Windows event collection and forwarding
- Troubleshooting communication between Splunk, Shuffle, Docker, and the VMware-hosted lab environment
- Parsing alert data within the SOAR workflow
- Configuring Slack and email notifications
- Implementing analyst approval
- Automating the Active Directory response action

### Key Takeaway

This project provided hands-on experience building an end-to-end SOC workflow, from **Windows authentication telemetry and SIEM detection to SOAR orchestration, analyst approval, and automated Active Directory response**.
