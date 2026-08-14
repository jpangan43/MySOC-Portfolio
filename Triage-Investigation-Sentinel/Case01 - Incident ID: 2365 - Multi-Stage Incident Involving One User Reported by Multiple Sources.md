# Incident ID: 2365 — Multi-Stage Incident Involving One User Reported by Multiple Sources

## Findings

| Field | Details |
|---|---|
| **Time** | 2026-07-10 14:51:36 UTC – 2026-07-11 02:15:10 UTC |
| **User** | `soc@mahcyberdefense.com` |
| **Primary Suspicious IP** | `2405:201:c40b:c0c9:3d38:dc4f:7cf8:d1fa` |
| **Location** | India |
| **Application** | One Outlook Web |
| **Authentication** | Single-factor authentication |
| **Risk Level** | Medium |
| **Risk State** | `atRisk` |
| **Device** | Windows 10 / Edge 150 |
| **Device Status** | Unmanaged / Noncompliant |
| **Result Code** | `50140` |
| **Correlation ID** | `a9223362-0258-8a59-4706-c58ba0ac08d0` |

---

## Investigation

Between 2026-07-10 14:51:36 UTC and 2026-07-11 02:15:10 UTC, the account `soc@mahcyberdefense.com` was observed authenticating to Microsoft 365 / One Outlook Web from multiple geographic locations, including the United States, India, United Kingdom, and Germany.

The primary activity of concern originated from the IPv6 address:

`2405:201:c40b:c0c9:3d38:dc4f:7cf8:d1fa`

The IP address was associated with India.

The India-based authentication activity showed:

- Medium sign-in risk
- `atRisk` account state
- Single-factor authentication
- Windows 10 device
- Unmanaged/noncompliant device

Several authentication events from this IP returned ResultType `50140`. Investigation of the result description showed that these events were associated with a "Keep me signed in" authentication interruption.

The events also shared the same Correlation ID, indicating that they were related to the same authentication flow. Therefore, these events were not classified as brute-force or password-guessing attempts.

Additional investigation of `OfficeActivity` and `AuditLogs` returned no results for the investigated period.

Based on the available telemetry, there is insufficient evidence to confirm account compromise or determine what activity occurred after authentication.

---

## WHO

User: `soc@mahcyberdefense.com`

The investigation focused on suspicious authentication activity associated with this Microsoft 365 account.

---

## WHAT

The account showed suspicious authentication activity from multiple geographic locations.

The primary activity of concern originated from an IP address in India and included:

- Medium sign-in risk
- `atRisk` account state
- Single-factor authentication
- Unmanaged/noncompliant Windows device
- Multiple authentication events returning ResultType `50140`

---

## WHEN

The suspicious activity occurred between July 10 and July 11, 2026 UTC.

### Significant Events

| Timestamp (UTC) | Event |
|---|---|
| 2026-07-10 16:03:10 | Medium-risk authentication from India |
| 2026-07-10 16:09:13 | `atRisk` authentication from India |
| 2026-07-10 16:09:15 | `50140` authentication event |
| 2026-07-11 02:15:06 | `50140` authentication event |
| 2026-07-11 02:15:10 | `50140` authentication event |

Based on the available logs, it cannot be confirmed whether the activity continued after the investigation period.

---

## WHERE

The activity occurred within Microsoft 365 / Microsoft Entra ID, primarily through One Outlook Web.

### Primary Suspicious Source

**IP Address:** `2405:201:c40b:c0c9:3d38:dc4f:7cf8:d1fa`  
**Location:** India

### Other Observed Locations

- United States
- India
- United Kingdom
- Germany

---

## WHY

The reason for the unusual geographic authentication activity could not be determined from the available Sentinel telemetry.

Possible explanations include:

- Legitimate user activity
- VPN or proxy infrastructure
- Travel or geographic IP misclassification
- Unauthorized account activity

Additional user validation and telemetry would be required to determine the cause.

---

## HOW

The account authenticated to Microsoft 365 from multiple IP addresses and geographic locations using single-factor authentication.

The primary suspicious authentication originated from an unmanaged/noncompliant Windows device.

The `50140` events were subsequently identified as "Keep me signed in" authentication interruptions rather than failed password attempts or brute-force activity.

---

# Recommendations

### 1. Validate the Activity

Contact the user and confirm whether the India-based authentication was legitimate.

Determine whether the user was:

- Physically located in India
- Using a VPN
- Using a corporate proxy
- Using another service that could explain the geographic location

### 2. Treat as Potentially Compromised if Unrecognized

If the user denies the activity:

- Reset the account password
- Revoke active sessions/tokens
- Review authentication methods
- Follow the organization's incident-response procedure

### 3. Enforce MFA

Enable or enforce Multi-Factor Authentication (MFA) for `soc@mahcyberdefense.com` and review the account's existing authentication methods.

### 4. Review Conditional Access

Review Conditional Access policies to ensure that:

- Risky sign-ins are appropriately restricted
- Unmanaged devices are restricted
- Noncompliant devices cannot access sensitive resources
- MFA is required for risky authentication scenarios

### 5. Search for the Suspicious IP

Search the environment for other accounts that may have authenticated from the same IP address:

```kql
SigninLogs
| where IPAddress == "2405:201:c40b:c0c9:3d38:dc4f:7cf8:d1fa"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ResultType,
    RiskLevelDuringSignIn,
    RiskState
| order by TimeGenerated asc
```

### 6. Continue Monitoring

Continue monitoring the account for:

- Unfamiliar geographic locations
- New suspicious IP addresses
- Unmanaged devices
- Medium/high-risk authentication events
- Multiple authentication failures
- Suspicious post-authentication activity

---

# Final Assessment

**Classification:** `Suspicious Account Activity — Requires Validation`

The available evidence indicates suspicious authentication activity, but it does not conclusively demonstrate account compromise.

The `50140` events were determined to be authentication-flow interruptions associated with "Keep me signed in", and therefore should not be classified as brute-force or password-guessing activity.

Further validation with the user and additional telemetry are required before confirming or closing the incident.

---

# KQL Queries Used

## 1. Review Account Sign-ins

```kql
SigninLogs
| where UserPrincipalName =~ "soc@mahcyberdefense.com"
| where TimeGenerated between (
    datetime(2026-07-10 14:00:00)
    ..
    datetime(2026-07-11 03:00:00)
)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ResultType,
    ResultDescription,
    RiskLevelDuringSignIn,
    RiskState,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    DeviceDetail,
    UserAgent
| order by TimeGenerated asc
```

## 2. Investigate the Suspicious India IP

```kql
SigninLogs
| where UserPrincipalName =~ "soc@mahcyberdefense.com"
| where IPAddress == "2405:201:c40b:c0c9:3d38:dc4f:7cf8:d1fa"
| project
    TimeGenerated,
    IPAddress,
    Location,
    AppDisplayName,
    ResultType,
    ResultDescription,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    RiskState,
    CorrelationId,
    DeviceDetail,
    UserAgent
| order by TimeGenerated asc
```

## 3. Identify At-Risk Sign-ins

```kql
SigninLogs
| where UserPrincipalName =~ "soc@mahcyberdefense.com"
| where TimeGenerated between (
    datetime(2026-07-10 14:00:00)
    ..
    datetime(2026-07-11 03:00:00)
)
| where RiskState == "atRisk"
| project
    TimeGenerated,
    IPAddress,
    Location,
    AppDisplayName,
    ResultType,
    ResultDescription,
    RiskLevelDuringSignIn,
    RiskState,
    CorrelationId,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    DeviceDetail,
    UserAgent
| order by TimeGenerated asc
```

## 4. Compare Activity by IP

```kql
SigninLogs
| where UserPrincipalName =~ "soc@mahcyberdefense.com"
| where TimeGenerated between (
    datetime(2026-07-10 14:00:00)
    ..
    datetime(2026-07-11 03:00:00)
)
| summarize
    SignInCount = count(),
    SuccessCount = countif(ResultType == "0"),
    FailedCount = countif(ResultType != "0"),
    RiskEvents = countif(RiskState == "atRisk"),
    MediumRisk = countif(RiskLevelDuringSignIn == "medium"),
    Locations = make_set(Location),
    Apps = make_set(AppDisplayName)
    by IPAddress
| order by SignInCount desc
```

## 5. Validate the 50140 Events

```kql
SigninLogs
| where UserPrincipalName =~ "soc@mahcyberdefense.com"
| where IPAddress == "2405:201:c40b:c0c9:3d38:dc4f:7cf8:d1fa"
| where ResultType == "50140"
| project
    TimeGenerated,
    IPAddress,
    ResultType,
    ResultDescription,
    AppDisplayName,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    RiskState,
    CorrelationId
| order by TimeGenerated asc
```

---

## MITRE ATT&CK Consideration

**Potential Technique:** `T1078 – Valid Accounts`

The authentication activity may warrant investigation under Valid Accounts because legitimate credentials appear to have been used from an unusual geographic location and an unmanaged device. However, the available evidence is insufficient to confirm credential compromise.

**Current Status:** `Suspicious / Requires Validation`
