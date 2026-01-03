# cybersecurity-portfolio


````markdown
# 🛡️ Cybersecurity Portfolio — Threat Detection, SOC & IR (Microsoft Security)

!Azure
!Microsoft Sentinel
!Defender for Endpoint
!PowerShell
!KQL

> **Author:** K N, Manuvardhan  
> **Role:** Analyst, IT Technical Services (Bangalore, India)  
> **Focus:** Threat Detection • Incident Response • Automation • Microsoft Security Stack (Sentinel, Defender, Azure/AD)

---

## 📌 Overview

This repository showcases hands-on projects, detections, automation scripts, and IR documentation built around the Microsoft security stack:

- **SIEM:** Microsoft Sentinel (Azure Sentinel)  
- **EDR/XDR:** Defender for Endpoint & Defender XDR  
- **Identity:** Azure AD / Entra ID  
- **Automation:** PowerShell + Logic Apps  
- **Logs:** Sysmon, Windows Event Logs, Azure Sign-in Logs

> Goal: Demonstrate practical capability in building detections, running investigations, and automating security operations.

---

## 🧭 Table of Contents

- Repo Structure
- About Me
- Skills
- Projects
- Detection Engineering
- Incident Response Docs
- Reports
- Setup & Usage
- Certifications
- Contact

---

## 🗂 Repo Structure

```text
cybersecurity-portfolio/
├─ README.md
├─ projects/
│  ├─ sentinel-lab-setup/
│  │  ├─ workbook-screenshots/
│  │  └─ connectors-notes.md
│  ├─ threat-hunting-kql/
│  │  ├─ abnormal-logins.kql
│  │  └─ lateral-movement.kql
│  ├─ incident-response-simulation/
│  │  ├─ evidence/
│  │  ├─ timeline.md
│  │  └─ IR-report.md
│  └─ powershell-automation/
│     ├─ enrich-iocs.ps1
│     └─ export-defender-alerts.ps1
├─ detections/
│  ├─ powershell-encoded-command.kql
│  ├─ brute-force-login.kql
│  └─ lsass-access-alert.kql
├─ docs/
│  ├─ playbooks/
│  │  ├─ phishing-playbook.md
│  │  └─ malware-containment.md
│  ├─ runbooks/
│  │  ├─ sentinel-investigation-runbook.md
│  │  └─ defender-triage-runbook.md
│  └─ tuning-notes.md
├─ reports/
│  ├─ phishing-investigation.md
│  ├─ hunting-weekly-summary.md
│  └─ threat-intel-iocs.md
└─ assets/
   ├─ screenshots/
   └─ diagrams/
````

***

## 👤 About Me

Cybersecurity Analyst specializing in **threat detection**, **incident response**, and **security automation** in Microsoft environments. Experienced with log collection, KQL hunting, Defender investigations, Sentinel analytics rules, and PowerShell scripting to improve SOC efficiency.

**Core interests:** Detection engineering • IR workflows • Automation • Blue Teaming

***

## 🛠 Skills

**Security Platforms**

*   Microsoft Sentinel (workbooks, analytics rules, playbooks)
*   Microsoft Defender for Endpoint (incidents, advanced hunting)
*   Microsoft Defender XDR / Cloud App Security
*   Azure AD / Entra ID (Conditional Access, PIM)

**Technical**

*   KQL (queries, hunting, rules, joins, parsing)
*   PowerShell (automation scripts, APIs, enrichment)
*   Log ingestion, normalization (Sysmon, Windows Events)
*   IR: triage → containment → remediation → post-incident review

**Soft Skills**

*   Clear documentation & stakeholder communication
*   Root-cause analysis under pressure
*   Cross-functional collaboration (IT, network, dev)

***

## 🚀 Projects

### 1) Microsoft Sentinel Lab Setup

**Objective:** Deploy a functional SIEM lab with **Log Analytics + Sentinel** and ingest endpoint telemetry (Sysmon).  
**Highlights:**

*   Connected Windows Security Events & Sysmon using agent
*   Built dashboards/workbooks for sign-ins, process events, and alerts
*   Integrated TI feeds and set up basic Analytics Rules

**Artifacts:**

*   `projects/sentinel-lab-setup/connectors-notes.md`
*   `assets/screenshots/` (workbooks/alerts)

***

### 2) Threat Hunting Using KQL

**Objective:** Hunt for abnormal logins and lateral movement across endpoints and identity logs.  
**Artifacts:**

*   `projects/threat-hunting-kql/abnormal-logins.kql`
*   `projects/threat-hunting-kql/lateral-movement.kql`

**Sample – Abnormal Logins**

```kql
SecurityEvent
| where EventID == 4624 // successful logon
| summarize attempts=count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where attempts > 30
| order by attempts desc
```

***

### 3) Incident Response Simulation (Malware + PowerShell)

**Scenario:** Suspicious PowerShell execution leading to malware dropper.  
**Workflow:**

*   Investigate **Defender for Endpoint** incident timeline and process tree
*   Extract **IoCs** (hashes, domains, registry keys)
*   Contain device, block hash, initiate scan, document lessons learned

**Artifacts:**

*   `projects/incident-response-simulation/timeline.md`
*   `projects/incident-response-simulation/IR-report.md`
*   Evidence in `projects/incident-response-simulation/evidence/`

***

### 4) PowerShell Automation – IoC Enrichment

**Objective:** Automate enrichment of file hashes against Defender incidents and export results.  
**Artifacts:**

*   `projects/powershell-automation/enrich-iocs.ps1`
*   `projects/powershell-automation/export-defender-alerts.ps1`

**Skeleton Script**

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$InputHashesCsv,
    [string]$OutputCsv = "ioc_enrichment_results.csv"
)

# TODO: Add authentication to Microsoft Graph/Defender API
# Connect-AzAccount or Connect-MgGraph as needed

$hashes = Import-Csv -Path $InputHashesCsv

$results = foreach ($h in $hashes) {
    # Placeholder enrichment logic
    [PSCustomObject]@{
        Hash          = $h.Hash
        FirstSeen     = (Get-Date).AddDays(- (Get-Random -Minimum 1 -Maximum 14))
        LastSeen      = Get-Date
        DefenderHits  = (Get-Random -Minimum 0 -Maximum 3)
        Status        = if ((Get-Random) % 2 -eq 0) {"Benign"} else {"Suspicious"}
    }
}

$results | Export-Csv -Path $OutputCsv -NoTypeInformation
Write-Host "Saved results to $OutputCsv"
```

***

## 🧩 Detection Engineering

### Detection: Suspicious PowerShell Encoded Commands

**Logic:** Detect usage of `-enc` in PowerShell indicating potential obfuscation.  
**File:** `detections/powershell-encoded-command.kql`

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-enc" or ProcessCommandLine has "-EncodedCommand"
| extend Device = tostring(DeviceName), User = tostring(InitiatingUser)
| project TimeGenerated, Device, User, FileName, ProcessCommandLine
```

### Detection: Brute-Force Login

**File:** `detections/brute-force-login.kql`

```kql
SigninLogs
| where ResultType != 0
| summarize failures=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where failures > 25
| order by failures desc
```

### Detection: LSASS Access Attempt (Credential Dumping)

**File:** `detections/lsass-access-alert.kql`

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("lsass", "comsvcs.dll", "MiniDump")
| where FileName in~ ("procdump.exe","rundll32.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

***

## 📚 Incident Response Docs

*   **Phishing Response Playbook:** `docs/playbooks/phishing-playbook.md`
*   **Malware Containment Playbook:** `docs/playbooks/malware-containment.md`
*   **Sentinel Investigation Runbook:** `docs/runbooks/sentinel-investigation-runbook.md`
*   **Defender Triage Runbook:** `docs/runbooks/defender-triage-runbook.md`

**Tuning Notes:** `docs/tuning-notes.md`

***

## 📄 Reports

*   **Phishing Investigation Report:** `reports/phishing-investigation.md`
*   **Weekly Hunting Summary:** `reports/hunting-weekly-summary.md`
*   **Threat Intel IoCs:** `reports/threat-intel-iocs.md`

***

## ⚙️ Setup & Usage

> These instructions assume an Azure subscription and basic familiarity with Sentinel/Defender.

1.  **Create Azure resources**
    *   Log Analytics Workspace
    *   Microsoft Sentinel enabled on workspace

2.  **Connect data sources**
    *   Windows Security Events (via agent)
    *   Sysmon (recommended config)
    *   Azure AD Sign-in Logs

3.  **Import Detections**
    *   Copy KQL files from `/detections` into Sentinel **Analytics Rules** (Scheduled/Custom)
    *   Tune thresholds and add suppression rules to reduce false positives

4.  **Threat Hunting**
    *   Use `/projects/threat-hunting-kql/*.kql` in **Sentinel Hunting** or **Defender Advanced Hunting**
    *   Save queries and convert high-confidence hunts into rules

5.  **Automation**
    *   Use `/projects/powershell-automation/*.ps1` with Microsoft Graph/Defender APIs
    *   Build **Logic Apps** playbooks for enrichment, ticketing, or containment steps

> **Note:** Replace placeholder scripts and thresholds with environment-specific logic.

***

## 🎓 Certifications

*   SC‑200 (Security Operations Analyst) — *planned/in-progress*
*   SC‑300 / AZ‑500 — *optional, based on role*
*   Security+ / CySA+ — *foundational*
*   Blue Team Level 1 — *hands-on SOC skills*

***

## 📬 Contact

*   **LinkedIn:** \[Add your profile link here]
*   **Email:** \[Add your email here]
*   **GitHub:** \[Add your GitHub username/repo link here]

***

## ✅ License

This repository is for educational and portfolio purposes. Content may be reused with attribution.  
**License:** MIT (optional)
```
