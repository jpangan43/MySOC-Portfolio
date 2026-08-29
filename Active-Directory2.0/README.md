Description:
Designed and implemented a SOC workflow to detect successful unauthorized login activity, investigate the alert, notify a SOC Analyst, and optionally disable the affected Active Directory user account.

The workflow collects telemetry from a Domain Controller and a Windows test machine, sends the logs to a Splunk Ubuntu Server, and uses Shuffle SOAR to automate alert handling and notification.

The SOC Analyst receives an alert through email/Slack and makes the final decision on whether the compromised or suspicious domain account should be disabled.
