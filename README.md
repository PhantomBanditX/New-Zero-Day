# New Zero-Day

## 1. Preparation

### Scenario

A recently discovered ransomware variant called `PwnCrypt` has been making headlines for its use of a PowerShell-based payload to encrypt files on compromised systems. The malware employs AES-256 encryption and focuses on specific folders, including `C:\Users\Public\Desktop`. Once encrypted, files are renamed with the original extension followed by `.pwncrypt`.

**Description:**

- The security program is immature and lacks basic user training.
- Newly discovered ransomware may have already entered the corporate network.

**Task:**

- Examine the potential spread of the new ransomware strain into the corporate network.

**Goal:**

- Uncover evidence of ransomware activity and trace its movement between devices.

---

### Components, Tools, and Technologies Employed

- **Cloud Environment:** Microsoft Azure (VM-Windows target machine)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
  

----

## 2. Detection & Analysis

### **Connection Failure Review**

Inspected file system activity for pwncrypt IoCs.
<br><br>
```kql
let PatientZero  = "cyberclaw-vm";
DeviceFileEvents
| where DeviceName == PatientZero 
| where FileName contains "pwncrypt"
| order by Timestamp desc  
```

<img alt="Image" src="https://github.com/user-attachments/assets/fe205cae-78aa-4162-ab61-63c870e87ada" />
<br><br>
<img alt="Image" src="https://github.com/user-attachments/assets/e7764953-ab6e-44e2-901d-75b357bf8c23" />
<br><br>
Findings: Files created on Desktop, then renamed in Temp within one second.

---

### **Network Forensics**

Reviewed process activity for pwncrypt-related execution.
<br><br>
```kql
let PatientZero  = "cyberclaw-vm";
let SpecificTime = datetime(2026-04-26T01:13:33.1636981Z);
DeviceProcessEvents
| where Timestamp between ((SpecificTime - 5m) .. (SpecificTime + 5m))
| where InitiatingProcessCommandLine contains "pwncrypt" or FolderPath contains "pwncrypt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine 
```
<img alt="Image" src="https://github.com/user-attachments/assets/61dc43d5-4aaf-4813-a802-4dd91d92ee8d" />

#### `Timestamp captured: 2026-04-26T01:13:33.1636981Z`

Findings: The attack chain: `cmd.exe` launched `powershell.exe` with execution policy bypass to run `C:\programdata\pwncrypt.ps1`, confirming the ransomware's delivery mechanism.

---

### **MITRE ATT&CK Mapping: Tactics, Techniques, and Procedures (TTPs)**

- [T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

- [T1685 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/)

- [T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

- [T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

- [T1027 – Obfuscated/Hidden Files and Information](https://attack.mitre.org/techniques/T1027/)


---

## 3. Response

This activity was not anticipated or authorized by administrators. The device was therefore immediately isolated, and a malware scan was initiated.
<br><br>
<img alt="Image" src="https://github.com/user-attachments/assets/fec87d32-350f-4395-a52e-58dfd8e1f151" />
<br><br>
Findings: The malware scan returned no findings. However, as a precautionary measure, the affected device was isolated and a support ticket was raised to reimage and rebuild the system. The device remains in an isolated state.

---

## 4. Documentation
Findings:

- PowerShell script `portscan.ps1` executed by user `br00klyn`
- Internal port scanning activity detected
- Excessive failed internal connection attempts from **cyberclaw-vm**
- Consistent with port scanning/reconnaissance
  
---

## 5. Improvement

- Implement PowerShell Security Controls
- Deploy Application Control (AppLocker or WDAC)
- Implement Network Segmentation & Asset Hygiene
- Establish Basic User Awareness Training

---
## 🧾Summary                   
An investigation into `cyberclaw-vm` identified an abnormal volume of failed internal connection attempts to itself and neighboring hosts. The pattern of activity was consistent with internal port scanning behavior and systematic probing of multiple systems. A PowerShell script `(portscan.ps1)` was executed by user **br00klyn** during the same timeframe as the suspicious activity. No malware was detected, but the host was isolated and scheduled for rebuild as a precaution.

---
## References
- [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
