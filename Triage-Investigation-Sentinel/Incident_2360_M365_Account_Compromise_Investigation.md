# Incident 2360 — Suspected Microsoft 365 Account Compromise

## Overview

**Incident ID:** 2360  
**Incident Type:** Suspected Microsoft 365 Account Compromise / Unauthorized Account Access  
**Affected User:** Zach Balrog  
**User Principal Name:** `zbalrog@mapletaxsolutions.ca`  
**User ID:** `d23fde5a-0b58-4130-8a88-8711028822af`  
**Investigation Period:** `2026-07-09 14:40:46 UTC` – `2026-07-11 20:46:57 UTC`  
**Primary Suspicious IP:** `51.89.208.6`  
**Additional IP:** `74.15.244.54`  
**Administrative IP:** `40.123.53.159`  
**Primary Application:** Microsoft Office / Microsoft Authentication Broker  
**Status:** Contained  
**Severity:** Medium–High  
**Confidence:** Moderate

---

## Executive Summary

The investigation identified repeated successful Microsoft 365 authentications involving **Zach Balrog** from IP address **`51.89.208.6`** between July 9 and July 11, 2026.

A `MailItemsAccessed` event was also reported for the account from **`74.15.244.54`**, indicating mailbox access. However, the available telemetry did not provide sufficient information to determine which mailbox items were accessed or whether the activity was malicious.

Multiple KQL investigations were performed to identify the possible initial access mechanism, credential attacks, account manipulation, phishing, mailbox persistence, OAuth/application persistence, and activity associated with the suspicious IP.

The investigation did **not** identify supporting evidence for:

- Password spraying against Zach
- Credential stuffing against Zach
- Phishing through the available email telemetry
- Pre-incident account manipulation
- Unauthorized authentication-method/MFA modification
- Inbox or transport-rule persistence
- Email-forwarding persistence
- OAuth/application persistence
- Administrative activity originating from `51.89.208.6`

Administrative containment was confirmed on July 11, 2026 through password reset and refresh-token invalidation.

The strongest MITRE ATT&CK mapping is **T1078.004 – Valid Accounts: Cloud Accounts**. **T1114 – Email Collection** is potentially applicable because of the reported mailbox-access activity.

---

# Findings

## Suspicious Authentication Activity

Repeated successful Microsoft Office authentications were observed from:

```text
51.89.208.6
```

Observed authentication times:

| UTC Time | Activity | IP |
|---|---|---|
| 2026-07-09 14:40:46 | Successful Microsoft Office authentication | `51.89.208.6` |
| 2026-07-09 22:06:46 | Successful Microsoft Office authentication | `51.89.208.6` |
| 2026-07-10 04:06:46 | Successful Microsoft Office authentication | `51.89.208.6` |
| 2026-07-10 11:17:47 | Successful Microsoft Office authentication | `51.89.208.6` |
| 2026-07-10 18:20:50 | Successful Microsoft Office authentication | `51.89.208.6` |
| 2026-07-11 00:40:50 | Successful Microsoft Office authentication | `51.89.208.6` |
| 2026-07-11 07:03:51 | Successful Microsoft Office authentication | `51.89.208.6` |
| 2026-07-11 14:11:52 | Successful Microsoft Office authentication | `51.89.208.6` |

## Mailbox Access

A `MailItemsAccessed` event was reported:

```text
2026-07-09 23:33:14 UTC
User: Zach Balrog
IP: 74.15.244.54
Operation: MailItemsAccessed
```

Additional `OfficeActivity` searches did not return results, so the specific mailbox items accessed could not be established.

---

# Investigation Timeline

| Time (UTC) | Event | Assessment |
|---|---|---|
| **Jul 9 14:40:46** | Zach successfully authenticated to Microsoft Office from `51.89.208.6` | Suspicious |
| **Jul 9 22:06:46** | Successful Microsoft Office authentication from `51.89.208.6` | Suspicious |
| **Jul 9 23:33:14** | `MailItemsAccessed` event from `74.15.244.54` | Investigate |
| **Jul 10 04:06:46** | Successful Microsoft Office authentication from `51.89.208.6` | Suspicious |
| **Jul 10 11:17:47** | Successful Microsoft Office authentication from `51.89.208.6` | Suspicious |
| **Jul 10 18:20:50** | Successful Microsoft Office authentication from `51.89.208.6` | Suspicious |
| **Jul 11 00:40:50** | Successful Microsoft Office authentication from `51.89.208.6` | Suspicious |
| **Jul 11 07:03:51** | Successful Microsoft Office authentication from `51.89.208.6` | Suspicious |
| **Jul 11 14:11:52** | Successful Microsoft Office authentication from `51.89.208.6` | Suspicious |
| **Jul 11 20:42:45** | `StsRefreshTokenValidFrom` updated | Containment |
| **Jul 11 20:43:11** | Administrative password reset | Containment |
| **Jul 11 20:44:43–20:44:44** | Password changes and refresh-token updates | Containment |
| **Jul 11 20:46:55** | Microsoft Authentication Broker authentication attempt from `74.15.244.54` | Post-remediation |
| **Jul 11 20:46:57** | Authentication failed: password expired | Consistent with containment |

---

# KQL Investigation

The following queries were used during the investigation.

## 1. Pre-Incident Search for Suspicious IP

Purpose: Determine whether `51.89.208.6` appeared before the first suspicious authentication.

```kql
SigninLogs
| where TimeGenerated between (
    datetime(2026-07-01) ..
    datetime(2026-07-09 14:40:46)
)
| where IPAddress == "51.89.208.6"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResultType,
    ResultDescription,
    ClientAppUsed,
    UserAgent
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** No sign-in activity from `51.89.208.6` was identified in the reviewed pre-incident period.

---

## 2. Failed Authentication / Possible Brute Force

Purpose: Identify repeated failed authentication that could indicate brute-force or password-spraying activity.

```kql
SigninLogs
| where TimeGenerated between (
    datetime(2026-07-01) ..
    datetime(2026-07-09 14:40:46)
)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Users = make_set(UserPrincipalName),
    IPs = make_set(IPAddress)
    by IPAddress
| where FailedAttempts >= 3
| order by FailedAttempts desc
```

**Result:** Results existed for other accounts, but no activity was identified that linked the failed authentication activity to Zach Balrog.

**Assessment:** Password spraying/brute-force activity against Zach was not confirmed.

---

## 3. Failed-to-Successful Authentication Correlation

```kql
let StartTime = datetime(2026-07-01);
let IncidentStart = datetime(2026-07-09 14:40:46);

let Failed =
SigninLogs
| where TimeGenerated between (StartTime .. IncidentStart)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    LastFailure = max(TimeGenerated)
    by IPAddress, UserPrincipalName;

let Successful =
SigninLogs
| where TimeGenerated between (StartTime .. IncidentStart)
| where ResultType == 0
| summarize
    FirstSuccess = min(TimeGenerated)
    by IPAddress, UserPrincipalName;

Failed
| join kind=inner Successful on IPAddress, UserPrincipalName
| where FirstSuccess > LastFailure
| project
    UserPrincipalName,
    IPAddress,
    FailedAttempts,
    LastFailure,
    FirstSuccess
| order by FirstSuccess asc
```

**Result:** A failed-to-successful authentication sequence was identified for another account, but it was not associated with Zach.

**Assessment:** No evidence connected password spraying or brute-force activity to Incident 2360.

---

## 4. Zach Account Modifications Before Incident

```kql
AuditLogs
| where TimeGenerated between (
    datetime(2026-07-01) ..
    datetime(2026-07-09 14:40:46)
)
| where TargetResources has "Zach Balrog"
   or TargetResources has "d23fde5a-0b58-4130-8a88-8711028822af"
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatedBy,
    TargetResources,
    CorrelationId
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** No pre-incident account modification involving Zach was identified.

---

## 5. Authentication Method / MFA Changes

```kql
AuditLogs
| where TimeGenerated between (
    datetime(2026-07-01) ..
    datetime(2026-07-09 14:40:46)
)
| where OperationName has_any (
    "authentication method",
    "Register",
    "Add",
    "Update"
)
| where TargetResources has "Zach Balrog"
   or TargetResources has "d23fde5a-0b58-4130-8a88-8711028822af"
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatedBy,
    TargetResources,
    CorrelationId
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** No evidence of unauthorized authentication-method or MFA modification was identified.

---

# Post-Authentication Investigation

## 6. Everything Zach Did After First Suspicious Authentication

This was the primary correlation query.

```kql
union isfuzzy=true
(
    SigninLogs
    | where TimeGenerated between (
        datetime(2026-07-09 14:40:46) ..
        datetime(2026-07-11 23:59:59)
    )
    | where UserId == "d23fde5a-0b58-4130-8a88-8711028822af"
       or UserPrincipalName has "zach"
    | project
        TimeGenerated,
        Source="SigninLogs",
        User=UserPrincipalName,
        IP=IPAddress,
        Activity=AppDisplayName,
        Details=ResultDescription
),
(
    AuditLogs
    | where TimeGenerated between (
        datetime(2026-07-09 14:40:46) ..
        datetime(2026-07-11 23:59:59)
    )
    | where TargetResources has "Zach Balrog"
       or TargetResources has "d23fde5a-0b58-4130-8a88-8711028822af"
    | project
        TimeGenerated,
        Source="AuditLogs",
        User=tostring(InitiatedBy.user.userPrincipalName),
        IP=tostring(InitiatedBy.user.ipAddress),
        Activity=OperationName,
        Details=ResultDescription
)
| order by TimeGenerated asc
```

### Significant Results

The query identified the administrative remediation sequence:

```text
2026-07-11 20:42:45 UTC
Steven@mydfir.com
74.15.244.54
Update StsRefreshTokenValidFrom Timestamp
```

Then:

```text
2026-07-11 20:43:11 UTC
Reset user password
```

and:

```text
2026-07-11 20:43:11 UTC
Reset password (by admin)
Successfully completed reset.
```

Additional password and refresh-token changes occurred around:

```text
2026-07-11 20:44:43–20:44:44 UTC
```

A subsequent authentication attempt occurred at:

```text
2026-07-11 20:46:55 UTC
User: zbalrog@mapletaxsolutions.ca
IP: 74.15.244.54
Application: Microsoft Authentication Broker
```

The following event occurred two seconds later:

```text
2026-07-11 20:46:57 UTC
The password is expired.
```

**Assessment:** The results strongly support administrative containment through password reset and refresh-token invalidation.

---

# Phishing Investigation

## 7. Search for Phishing Emails Received by Zach

```kql
EmailEvents
| where Timestamp between (
    datetime(2026-07-01) ..
    datetime(2026-07-09 14:40:46)
)
| where RecipientEmailAddress has "zach"
| project
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DetectionMethods,
    DeliveryAction,
    NetworkMessageId
| order by Timestamp asc
```

**Result:** No results.

**Assessment:** No phishing email was identified through the available email telemetry.

> This does not prove that phishing did not occur; it only means that the query did not identify supporting evidence.

---

# Suspicious IP Investigation

## 8. Search Audit Activity From `51.89.208.6`

```kql
AuditLogs
| where TimeGenerated between (
    datetime(2026-07-09 14:40:46) ..
    datetime(2026-07-11 20:42:45)
)
| where tostring(InitiatedBy.user.ipAddress) == "51.89.208.6"
| project
    TimeGenerated,
    InitiatedBy,
    OperationName,
    Result,
    ResultDescription,
    TargetResources,
    CorrelationId
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** No administrative/audit activity was identified as originating from `51.89.208.6`.

---

# Mailbox Investigation

## 9. Search for `MailItemsAccessed`

```kql
OfficeActivity
| where TimeGenerated between (
    datetime(2026-07-09 00:00:00) ..
    datetime(2026-07-12 00:00:00)
)
| where Operation == "MailItemsAccessed"
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    OfficeWorkload,
    Parameters
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** The original alert remains the available evidence for the `MailItemsAccessed` event.

---

## 10. Search OfficeActivity for `51.89.208.6`

```kql
OfficeActivity
| where TimeGenerated between (
    datetime(2026-07-09 00:00:00) ..
    datetime(2026-07-12 00:00:00)
)
| where ClientIP == "51.89.208.6"
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    OfficeWorkload,
    Parameters
| order by TimeGenerated asc
```

**Result:** No results.

---

## 11. Search OfficeActivity for `74.15.244.54`

```kql
OfficeActivity
| where TimeGenerated between (
    datetime(2026-07-09 00:00:00) ..
    datetime(2026-07-12 00:00:00)
)
| where ClientIP == "74.15.244.54"
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    OfficeWorkload,
    Parameters
| order by TimeGenerated asc
```

**Result:** No results.

---

# Persistence Investigation

## 12. Inbox / Transport Rule Persistence

```kql
OfficeActivity
| where TimeGenerated between (
    datetime(2026-07-09 14:40:46) ..
    datetime(2026-07-11 20:42:45)
)
| where UserId has_any (
    "ZBalrog",
    "zbalrog",
    "Zach"
)
| where Operation has_any (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules",
    "Set-Mailbox",
    "New-TransportRule",
    "Set-TransportRule"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    Parameters
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** No mailbox-rule or transport-rule persistence was identified.

---

## 13. Email Forwarding Persistence

```kql
OfficeActivity
| where TimeGenerated between (
    datetime(2026-07-09 14:40:46) ..
    datetime(2026-07-11 20:42:45)
)
| where UserId has_any (
    "ZBalrog",
    "zbalrog",
    "Zach"
)
| where Parameters has_any (
    "ForwardingAddress",
    "ForwardingSmtpAddress",
    "RedirectTo"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    Parameters
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** No evidence of email-forwarding persistence was identified.

---

# OAuth / Application Persistence

## 14. OAuth / Application Activity

```kql
AuditLogs
| where TimeGenerated between (
    datetime(2026-07-09 14:40:46) ..
    datetime(2026-07-11 23:59:59)
)
| where OperationName has_any (
    "consent",
    "OAuth",
    "permission",
    "service principal",
    "application"
)
| where TargetResources has "Zach Balrog"
   or TargetResources has "d23fde5a-0b58-4130-8a88-8711028822af"
   or InitiatedBy has "Zach"
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatedBy,
    TargetResources,
    CorrelationId
| order by TimeGenerated asc
```

**Result:** No results.

**Assessment:** No OAuth/application persistence involving Zach was identified.

---

# Security Alert Investigation

## 15. SecurityAlert During Remediation

```kql
union isfuzzy=true
(
    AuditLogs
    | where TimeGenerated between (
        datetime(2026-07-11 20:30:00) ..
        datetime(2026-07-11 20:50:00)
    )
    | where TargetResources has "Zach"
       or TargetResources has "ZBalrog"
    | project
        TimeGenerated,
        Source="AuditLogs",
        Activity=OperationName,
        User=tostring(InitiatedBy.user.userPrincipalName),
        Details=ResultDescription
),
(
    SecurityAlert
    | where TimeGenerated between (
        datetime(2026-07-11 20:30:00) ..
        datetime(2026-07-11 20:50:00)
    )
    | project
        TimeGenerated,
        Source="SecurityAlert",
        Activity=AlertName,
        User=CompromisedEntity,
        Details=Description
)
| order by TimeGenerated asc
```

**Result:** Audit activity was returned, but no corresponding `SecurityAlert` was identified.

---

# Investigation Results Summary

| Investigation Area | Result | Assessment |
|---|---|---|
| Pre-incident `51.89.208.6` activity | No results | IP not observed in reviewed pre-incident telemetry |
| Failed authentication against Zach | No results | Brute-force activity not confirmed |
| Password spraying | No Zach-related evidence | Not confirmed |
| Credential stuffing | No Zach-related evidence | Not confirmed |
| Zach account modification | No results | Not identified |
| Authentication/MFA modification | No results | Not identified |
| Phishing | No results | Not confirmed |
| Audit activity from `51.89.208.6` | No results | No administrative activity identified |
| `MailItemsAccessed` | Original alert only | Mailbox access reported |
| Mailbox rules | No results | Persistence not identified |
| Email forwarding | No results | Persistence not identified |
| OAuth/application persistence | No results | Persistence not identified |
| Password reset | **Confirmed** | Administrative containment |
| Refresh-token invalidation | **Confirmed** | Administrative containment |
| SecurityAlert during remediation | No results | No corresponding alert identified |

---

# WHO / WHAT / WHEN / WHERE / WHY / HOW

## WHO

**Affected User:** Zach Balrog  
**UPN:** `zbalrog@mapletaxsolutions.ca`  
**User ID:** `d23fde5a-0b58-4130-8a88-8711028822af`

**Administrator involved in remediation:** `Steven@mydfir.com`

## WHAT

The account exhibited repeated successful Microsoft 365 authentication from `51.89.208.6`.

A `MailItemsAccessed` event was reported for the account.

The account was subsequently subjected to password reset and refresh-token invalidation.

No confirmed attacker persistence was identified.

## WHEN

**Suspicious activity:** July 9–11, 2026

**Mailbox access alert:** July 9, 2026 23:33:14 UTC

**Administrative containment:** July 11, 2026 20:42:45–20:46:57 UTC

## WHERE

The activity occurred within the user's Microsoft 365 environment.

- **Primary suspicious IP:** `51.89.208.6`
- **Additional IP:** `74.15.244.54`
- **Administrative IP observed:** `40.123.53.159`

The investigation does not currently establish any of these IP addresses as definitively malicious.

## WHY

The intent behind the authentication activity cannot be conclusively determined.

The available telemetry does not establish how the credentials were obtained or whether the activity was performed by the legitimate user.

## HOW

The available evidence indicates repeated successful use of Zach's legitimate Microsoft 365 account from `51.89.208.6`.

This is consistent with potential unauthorized use of a valid cloud account.

The exact credential-compromise mechanism remains unknown.

The incident was subsequently contained through administrative password reset and refresh-token invalidation.

---

# MITRE ATT&CK Mapping

| Tactic | Technique | Assessment | Evidence |
|---|---|---|---|
| **Initial Access** | **T1078.004 – Valid Accounts: Cloud Accounts** | **Potentially applicable / Strongest mapping** | Successful Microsoft 365 authentication using Zach's legitimate cloud account from `51.89.208.6`. |
| **Credential Access** | **T1110 – Brute Force** | **Not confirmed** | No evidence of brute-force activity against Zach. |
| **Credential Access** | **T1110.003 – Password Spraying** | **Not confirmed** | No password-spraying activity linked to Zach. |
| **Collection** | **T1114 – Email Collection** | **Potentially applicable** | Original alert reported `MailItemsAccessed` activity. |
| **Collection** | **T1114.002 – Remote Email Collection** | **Potentially applicable** | Microsoft 365 mailbox access was reported, but malicious intent was not established. |
| **Persistence** | **T1098 – Account Manipulation** | **Not confirmed** | No pre-incident account manipulation identified. |
| **Persistence** | **T1098.005 – Device Registration** | **Not confirmed** | No unauthorized device registration identified. |
| **Persistence** | **T1136.003 – Create Account: Cloud Account** | **Not confirmed** | No evidence of attacker-created cloud accounts. |
| **Persistence** | **Mailbox Rules** | **Not confirmed** | No inbox or transport-rule persistence identified. |
| **Persistence** | **OAuth/Application Persistence** | **Not confirmed** | No supporting OAuth/application activity identified. |
| **Credential Access / Defense Evasion** | **T1550.001 – Use Alternate Authentication Material: Application Access Token** | **Not confirmed** | Refresh-token changes were part of administrative containment rather than confirmed attacker activity. |

---

# Recommendations

1. **Validate `51.89.208.6`** against Zach's legitimate location, device, VPN, and network information.

2. **Review individual sign-in events** for device ID, geographic location, user agent, authentication requirement, Conditional Access result, and session details.

3. **Review additional Exchange audit data** if available to determine exactly what mailbox items were accessed.

4. **Verify Zach's MFA configuration** and remove any unauthorized authentication methods or devices.

5. **Review OAuth application consent** and connected applications associated with the account.

6. **Search the wider tenant for `51.89.208.6`** to determine whether other accounts were accessed from the same IP.

7. **Continue monitoring Zach's account** for renewed suspicious authentication.

8. **Maintain password-reset and token-invalidation controls** until the activity is confirmed as legitimate.

9. **Do not automatically classify `74.15.244.54` as malicious**, because it was also associated with administrative remediation.

10. **Preserve relevant Microsoft 365 and Entra audit logs** for potential follow-up investigation.

---

# Final Assessment

**Incident Classification:** Suspected Microsoft 365 Account Compromise / Unauthorized Account Access

**Severity:** Medium–High

**Confidence:** Moderate

**Primary MITRE ATT&CK Technique:** **T1078.004 – Valid Accounts: Cloud Accounts**

**Potential Secondary Technique:** **T1114 – Email Collection**

**Initial Access Method:** Unknown

**Credential Access:** Suspected, not directly observed

**Persistence:** Not confirmed

**Mailbox Access:** Reported by original alert

**Data Exfiltration:** Not established

**Containment:** Confirmed

**Current Status:** Contained

## Analyst Conclusion

> The investigation identified repeated successful Microsoft 365 authentications involving Zach Balrog from `51.89.208.6` between July 9 and July 11, 2026. The activity is suspicious and consistent with potential unauthorized use of the legitimate cloud account. A `MailItemsAccessed` event was also reported for the account, indicating mailbox activity; however, the available telemetry did not provide sufficient information to determine which mailbox items were accessed or whether the activity was malicious.
>
> KQL investigation identified no supporting evidence of password spraying, credential stuffing, phishing, pre-incident account manipulation, authentication-method modification, inbox-rule persistence, email forwarding, OAuth/application persistence, or administrative activity originating from `51.89.208.6`.
>
> On July 11, administrative containment was confirmed through password reset and refresh-token invalidation. The evidence therefore supports a classification of suspected Microsoft 365 account compromise/unauthorized account access. **T1078.004 – Valid Accounts: Cloud Accounts** is the strongest MITRE ATT&CK mapping. **T1114 – Email Collection** is potentially applicable because of the reported mailbox-access activity, but malicious collection and data exfiltration could not be conclusively established.
>
> The initial credential-compromise mechanism and any attacker-controlled persistence remain undetermined based on the available telemetry.

---

## Evidence Limitations

This investigation is based on the telemetry and alert data available during the investigation.

A **no-result KQL query does not prove that an activity did not occur**. It indicates that the queried data source did not return matching records for the specified time range and filters.

The following remain undetermined:

- Exact source of the compromised credentials
- Whether `51.89.208.6` was attacker-controlled
- Exact mailbox items accessed
- Whether email data was exfiltrated
- Whether phishing occurred outside the available telemetry
- Whether persistence existed outside the queried data sources

---

## Portfolio Takeaways

### Detection Skills Demonstrated

- Microsoft Entra ID / Azure AD sign-in investigation
- Microsoft 365 account compromise investigation
- KQL-based timeline reconstruction
- Suspicious IP investigation
- Authentication analysis
- AuditLog investigation
- Mailbox activity investigation
- Persistence hunting
- OAuth/application persistence hunting
- Password-spraying investigation
- Phishing investigation
- MITRE ATT&CK mapping
- Incident containment analysis

### Primary Investigation Workflow

```text
Suspicious Authentication
        |
        v
Identify User + IP
        |
        v
Build Authentication Timeline
        |
        v
Search Pre-Incident Activity
        |
        v
Investigate Credential Attacks
        |
        v
Investigate Phishing
        |
        v
Investigate Account/MFA Changes
        |
        v
Investigate Mailbox Access
        |
        v
Hunt for Persistence
        |
        v
Correlate Audit Activity
        |
        v
Identify Containment Actions
        |
        v
MITRE ATT&CK Mapping
        |
        v
Final Assessment
```
