<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<!-- Mascots Section (optional) -->
<!--
<p align="center">
  <img src="https://github.com/user-attachments/assets/your-mascot-id.png" alt="Mascot" width="100">
</p>
-->

<h1 align="center">Internal Threat Hunting: Port Scanning Detection with Microsoft Defender for Endpoint</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-00B388?style=for-the-badge&logo=microsoft&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Threat%20Hunting-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

## Project Objective
> This project simulates a real-world internal threat hunting scenario using Microsoft Defender for Endpoint (MDE). The goal is to detect port scanning activity, investigate network degradation, and respond to potential lateral movement attempts across a Windows 10 virtual environment.

---

## Tools & Technologies
- **Platform:** Azure
- **OS:** Windows 10
- **Tools:** Microsoft Defender for Endpoint (MDE), Kusto Query Language (KQL)
- **Languages/Scripts:** PowerShell

---

## Skills Gained / Focus Areas
- Built custom KQL queries to detect excessive failed connections  
- Correlated network, file, and process events  
- Investigated suspicious activity using MITRE ATT&CK TTPs  
- Executed threat containment and isolation steps  

---

## Environment Setup
> A Windows 10 virtual machine was provisioned in Azure and onboarded to MDE. A simulated threat was introduced using a PowerShell port scanning script to generate logs and test detection capabilities.

---

## Walkthrough
1. [Step 1: Initial Setup](#step-1-initial-setup)
2. [Step 2: Configure the Environment](#step-2-configure-the-environment)
3. [Step 3: Execute the Hunt](#step-3-execute-the-hunt)
4. [Step 4: Analyze and Respond](#step-4-analyze-and-respond)

---

### Step 1: Initial Setup
> Created a Windows 10 VM in Azure and onboarded it to Microsoft Defender for Endpoint using the onboarding package. Executed the PowerShell port scanning script to simulate malicious activity:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1'
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```
![Step 1: Execute the Hunt](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-2-Sudden-Network-Slowdowns/main/images/S2SNS3.png)



---

### Step 2: Configure the Environment
> Allowed internal traffic by default. No egress restrictions were configured. PowerShell and common scripting tools were unrestricted. This created a realistic environment for lateral movement and port scanning detection.

---

### Step 3: Execute the Hunt
> Used KQL to identify suspicious patterns of failed connections and sequential port access attempts:

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, LocalIP, RemoteIP, RemotePort
| order by ConnectionCount desc
```
![Image 5](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-2-Sudden-Network-Slowdowns/main/images/S2SNS5.png)

> Queried process events around the time of anomalous network activity:

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2024-10-18T04:09:37.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
```

![Image 7](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-2-Sudden-Network-Slowdowns/main/images/S2SNS7.png)
---

### Step 4: Analyze and Respond
> The device `Cavada-cyber-pc` initiated multiple failed connections in sequence, indicating port scanning behavior. The port scan was executed via PowerShell running under the SYSTEM account. No malware was detected, but the device was isolated out of caution and submitted for reimaging.

---

## Outcomes and Lessons Learned
- **Technical Insight:** Port scanning activity creates detectable patterns of sequential failed connections. KQL queries allowed precise identification of the threat.  
- **Configuration Skills:** Practiced onboarding to MDE and isolating endpoints in response to threats.  
- **Troubleshooting:** Verified network slowdowns were not external. Found internal host misusing PowerShell.  
- **Takeaway:** Unrestricted internal traffic and scripting tools present high risks for lateral movement. Proper alerting and segmentation are critical.  

---

## References
- [Microsoft Defender for Endpoint Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Kusto Query Language (KQL) Docs](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [Port Scanning PowerShell Script (for simulation)](https://github.com/joshmadakor1/lognpacific-public)
