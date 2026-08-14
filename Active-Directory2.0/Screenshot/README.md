# Active-Directory-2.0

## Overview

This project demonstrates an end-to-end SOC detection and automated incident response workflow built in a VMware-based Active Directory lab.

The workflow detects successful RDP logins using Splunk and Windows Security Event Logs, sends the detection to Shuffle SOAR, notifies the SOC through Slack, and performs an automated Active Directory account-disabling action using the affected username.

## Project Objectives

The primary objective was to demonstrate how a SOC analyst can combine SIEM detection, SOAR automation, real-time notification, and Active Directory response into a single workflow.

The project also demonstrates practical skills in:

- Security event analysis
- RDP authentication detection
- Splunk alerting
- SOAR workflow development
- Active Directory integration
- LDAP connectivity
- Docker troubleshooting
- Slack API integration
- Automated incident response
- Dynamic data mapping using $exec.result.user

## Tools/Technologies used
- VMware — Used to host and manage the virtual machines for the SOC lab environment.
- Windows Server / Active Directory Domain Services (AD DS) — Used to create and manage the MYDFIRLAB.LOCAL domain, users, and authentication.
- Windows Client / Test Machine — Used to generate authentication activity and simulate an enterprise endpoint.
- Splunk Enterprise — Used as the SIEM platform for collecting Windows security events, analyzing authentication activity, and generating alerts.
- Splunk Search Processing Language (SPL) — Used to search and analyze Windows Event ID 4624 and identify successful RDP logons.
- Shuffle SOAR — Used to automate the incident response workflow and connect Splunk, Slack, and Active Directory.
- Shuffle Webhooks — Used to receive Splunk alert data and pass dynamic event information through the SOAR workflow.
- Shuffle Active Directory Integration — Used to query AD users and perform account-disabling actions.
- LDAP / LDAPS — Used to provide connectivity between Shuffle and the Active Directory domain controller.
- Docker — Used to run and troubleshoot Shuffle services and establish the required network connectivity.
- Slack — Used as the SOC notification platform for sending real-time suspicious-login alerts.
- Slack API (chat.postMessage) — Used by the Shuffle workflow to send automated notifications to the designated Slack channel.
- PowerShell — Used for Active Directory verification, domain information, service checks, and account validation.
- Windows Event Logs — Used as the primary telemetry source for authentication detection.

## Key findings
- Successfully built an on-premises SOC lab using VMware with Active Directory, Windows test machines, and Splunk.
- Successfully configured Splunk to detect successful RDP logins using Windows Event ID 4624 and Logon Type 10.
- Developed the MyDFIR-Unauthorized-Successful-Login-RDP detection to identify suspicious authentication activity.
- Successfully integrated Splunk with Shuffle SOAR using a webhook to automatically forward alert information.
- Successfully integrated Shuffle with Slack for real-time SOC alert notifications.
- Successfully connected Shuffle to Active Directory through LDAP and verified connectivity on ports 389 and 636.
- Successfully tested Active Directory user lookup and account-disabling actions through Shuffle.
- Implemented dynamic username mapping using $exec.result.user, allowing Shuffle to identify and respond to the affected AD account automatically.
- Successfully tested automated account disabling using the safe test account jsmith.
- Demonstrated an end-to-end SOC workflow from detection → alert → notification → automated response.
- Demonstrated practical experience with SIEM, SOAR, Active Directory, LDAP, alert automation, and incident response in a simulated enterprise environment.
- Identified the importance of using disposable test accounts and analyst approval before enabling automated account-disabling actions in a production environment.

## Lessons learned and challenges
- Learned how to build and troubleshoot an end-to-end SOC automation workflow using Active Directory, Splunk, Shuffle SOAR, and Slack.
- Learned how to configure Windows Event Log collection and Splunk detection logic for successful RDP authentication.
- Learned the importance of understanding Windows Event ID 4624 and Logon Type 10 when investigating RDP authentication activity.
- Encountered challenges connecting Shuffle SOAR to the Active Directory environment, particularly with Docker networking and connectivity between the Shuffle worker and the domain controller.
- Troubleshot Docker containers and networks to ensure the Shuffle worker could communicate with the Active Directory server.
- Verified LDAP connectivity using port 389 and LDAPS connectivity using port 636.
- Encountered issues with the Shuffle Active Directory app where incorrect or unsupported parameters caused errors such as unexpected keyword argument.
- Learned that Shuffle app actions must match the actual parameters supported by the installed app version.
- Troubleshot Slack API integration issues, including invalid parameters and missing required fields such as channel.
- Learned to validate API responses instead of relying only on the Shuffle workflow showing a successful execution.
- Encountered issues with the User Input/approval feature, which was ultimately set aside so the core SOC automation workflow could be completed and validated first.
- Learned the importance of testing individual workflow components before combining them into a complete automated response.
- Learned to use a safe test account (jsmith) when testing automated Active Directory account disabling instead of risking a privileged account.
- Learned that automated response actions should be carefully controlled because an incorrect username mapping or detection could potentially disable the wrong account.
- Gained practical experience troubleshooting SIEM-to-SOAR integrations, Docker-based services, LDAP connectivity, API requests, and dynamic variables.
- The biggest lesson was that successful SOC automation requires not only detection logic, but also reliable data mapping, connectivity, API compatibility, validation, and safe testing procedures.

