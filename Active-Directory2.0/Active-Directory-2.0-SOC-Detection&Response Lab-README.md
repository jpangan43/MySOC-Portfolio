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
| Hypervisor | Hyper-V |
| Network | Isolated/Internal Lab Network |

## Virtual Machines

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

1. Create a new Generation 2 virtual machine in Hyper-V.
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

1. Create a Windows 11 virtual machine.
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

Configure the lab network so that all virtual machines can communicate with each other.

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
- Troubleshooting communication between Splunk and Shuffle
- Parsing alert data within the SOAR workflow
- Configuring Slack and email notifications
- Implementing analyst approval
- Automating the Active Directory response action

### Key Takeaway

This project provided hands-on experience building an end-to-end SOC workflow, from **Windows authentication telemetry and SIEM detection to SOAR orchestration, analyst approval, and automated Active Directory response**.
