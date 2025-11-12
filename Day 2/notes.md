# SOC Lab – Splunk & Sysmon Hands-on

## Work Summary

- Installed **Sysmon** on one host (`win10_host`) using the [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config).
- Installed Splunk Add-ons:
  - [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742)
  - [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/3001)
  - [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)

### Baseline Running Processes (Sysmon)

This query lists the currently running processes on Windows hosts using Sysmon, showing process names, command lines, and parent processes for monitoring and investigation.

```
index=win10_host sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| stats count by Image, CommandLine, ParentImage
| sort - count
```

## Queries and Detections

The following queries and detections were created to monitor and analyze critical security events on Windows hosts.

### 1. Brute-force / Credential Stuffing
```
index=win10_host EventCode=4625
| bin _time span=5m
| stats dc(Source_Network_Address) as src_count, count as fails by Account_Name, _time
| where fails >= 5
```

### 2. Successful Login After Multiple Failures
```
index=win10_host (EventCode=4625 OR EventCode=4624)
| sort 0 _time
| streamstats window=6 current=f count(eval(EventCode==4625)) as recent_failures by Account_Name
| where EventCode==4624 AND recent_failures>=3
```

### 3. New Local User Creation
```
index=win10_host (EventCode=4625 OR EventCode=4624)
| sort 0 _time
| streamstats window=6 current=f count(eval(EventCode==4625)) as recent_failures by Account_Name
| where EventCode==4624 AND recent_failures>=3
```

### 4. Sensitive Command Execution (PowerShell, Certutil)
```
index=win10_host (CommandLine="*powershell*" OR CommandLine="*certutil*")
| stats count by Computer, User, CommandLine
```

### 5. Log Clear / Audit Policy Changes
```
index=win10_host EventCode=1102 OR EventCode=4719
| stats count by _time, ComputerName, Account_Name, EventCode
| where count >= 1
```
