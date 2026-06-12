# Hunting Brute Force Attempts on an Internet-Exposed VM

A hands-on threat hunt run through Microsoft Defender for Endpoint. A virtual machine in a shared services cluster was mistakenly exposed to the public internet. This project hunts for brute force login attempts against it and determines whether any attacker actually got in.

> Note: hostnames and account names in this writeup have been sanitized. Source IPs shown are the external attackers, kept as indicators of compromise.

| | |
|---|---|
| **Platform** | Microsoft Defender for Endpoint (Advanced Hunting) |
| **Query Language** | KQL |
| **Tactic** | Credential Access |
| **MITRE Technique** | T1110 Brute Force |
| **Outcome** | Brute force attempted, no successful breach |

## Contents

- [Background](#background)
- [Hypothesis](#hypothesis)
- [The Hunt](#the-hunt)
- [Findings](#findings)
- [Timeline](#timeline)
- [Indicators of Compromise](#indicators-of-compromise)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Response](#response)
- [Lessons and Improvements](#lessons-and-improvements)
- [Files](#files)

## Background

During routine maintenance, the security team investigates VMs in the shared services cluster (DNS, Domain Services, DHCP) that may have been mistakenly exposed to the public internet. The goal is to identify misconfigured VMs and check for brute force login attempts or successes from external sources.

The device in scope, `WIN-TARGET-01`, was confirmed internet-facing for roughly three days. While exposed, an internet-facing VM with network logon reachable will get discovered by bots and hammered with login attempts. The question this hunt answers is whether any of those attempts succeeded.

## Hypothesis

While `WIN-TARGET-01` was unknowingly exposed to the internet, an external attacker may have brute forced their way in, since older devices in the environment do not have account lockout configured for excessive failed logins.

## The Hunt

The hunt follows a structured lifecycle: build the hypothesis, collect the data, analyze it, investigate what turns up, respond, and document.

### Step 1: Confirm the exposure

```kql
DeviceInfo
| where DeviceName == "WIN-TARGET-01"
| where IsInternetFacing == true
| order by Timestamp desc
```

Confirmed the device was internet-facing. Last internet-facing instance was `2026-06-10T07:19:25Z`, with exposure running about three days.

### Step 2: Find the failed logons

```kql
DeviceLogonEvents
| where DeviceName == "WIN-TARGET-01"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

Over 100 failed login attempts came in from external IPs. Attempted usernames included `user1`, `Admin`, and `administrator`. These are the first accounts a brute force tool or bot goes after, which confirms automated brute force behavior.

### Step 3: Check if any attacker IP succeeded

```kql
let RemoteIPsInQuestion = dynamic(["194.180.48.149","143.92.36.175", "80.94.95.83", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

Took the top offending IPs and checked every one for a successful login. None succeeded.

### Step 4: Review all successful logons to the box

```kql
DeviceLogonEvents
| where DeviceName == "WIN-TARGET-01"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
```

Every successful login came from inside the network under a single internal account.

### Step 5: Confirm the internal logons are legitimate

```kql
DeviceLogonEvents
| where DeviceName == "WIN-TARGET-01"
| where LogonType has_any("Network")
| where ActionType == "LogonSuccess"
| where AccountName == "<internal-account>"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

Only 4 successful logons for the internal account, all from expected internal sources. Nothing unusual, nothing external.

## Findings

The device was clearly targeted by brute force while exposed to the internet, with 100+ failed attempts against common usernames. Despite that, there is no evidence of a successful breach. The only successful logons trace back to a single internal account and all were normal. The hypothesis was tested and not confirmed. The VM held.

## Timeline

| Time (UTC) | Event |
|------------|-------|
| ~June 7, 2026 | `WIN-TARGET-01` becomes internet-facing (exposure begins, ~3 day window) |
| Exposure window | 100+ failed network logons from external IPs using `Admin`, `administrator`, `user1` |
| 2026-06-10 07:19:25 | Last confirmed internet-facing instance |
| June 12 to 13, 2026 | Threat hunt conducted, no breach found |

## Indicators of Compromise

External attacker source IPs observed in the failed logon attempts:

| Type | Value |
|------|-------|
| IP | 194.180.48.149 |
| IP | 143.92.36.175 |
| IP | 80.94.95.83 |
| IP | 121.30.214.172 |
| IP | 83.222.191.62 |
| IP | 45.41.204.12 |
| IP | 192.109.240.116 |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----|
| Reconnaissance | Active Scanning | T1595 | Device discovered and targeted by bots after being exposed to the public internet |
| Initial Access | External Remote Services | T1133 | Attackers attempted network logon against an internet-exposed remote service |
| Credential Access | Brute Force | T1110 | 100+ failed logins from external IPs |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Repeated attempts against common usernames (`Admin`, `administrator`, `user1`) |
| Persistence / Defense Evasion | Valid Accounts | T1078 | The objective of the brute force, not achieved. No external success observed |

## Response

No compromise occurred, so this is containment and hardening rather than incident recovery:

- Remove the device from internet exposure. It should never have had a public-facing attack surface for network logon.
- Block the offending external IPs at the network boundary.
- Enable an account lockout policy so repeated failed logins lock the account before brute force can run its course.
- Restrict remote logon to a VPN or trusted IP ranges instead of the open internet.
- Enforce strong, unique passwords so guessing is not viable even if an account is reachable.

## Lessons and Improvements

**What would have prevented this:**

- The root cause was exposing a VM to the public internet with network logon reachable. Keeping it off the public internet removes the attack surface entirely.
- Account lockout is the control that stops brute force from running indefinitely.
- A network logon service should sit behind a VPN or a firewall rule limiting it to known IPs.

**What would sharpen the next hunt:**

- Capture exact timestamps for the first and last failed attempt per IP to build a tighter timeline.
- Cross-reference the attacker IPs against threat intel feeds to see if they are known bad actors.
- Build a scheduled detection rule for repeated failed logons on internet-facing devices so this gets flagged automatically instead of found during manual review.

## Files

- `README.md` - this writeup
- `queries.kql` - every KQL query used in the hunt

---

Part of an ongoing series of threat hunting and SOC investigations by Mohamed Yagoub.

