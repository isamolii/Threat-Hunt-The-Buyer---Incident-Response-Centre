# Threat Hunt Report: Ashford Sterling Recruitment - Akira Ransomware Incident
https://github.com/isamolii/Threat-Hunt-The-Buyer---Incident-Response-Centre/blob/main/README.md

**Hunter:** Isaias Molina  
**Date:** March 2026  
**Platform:** Microsoft Defender for Endpoint + Microsoft Sentinel (Advanced Hunting)  
**Lab:** Ashford Sterling Recruitment (Akira Ransomware) – Sequel to "The Broker"

## Executive Summary

Akira ransomware (active since ~2023) made a return visit to the Ashford Sterling Recruitment environment, leveraging pre-staged access from the earlier "The Broker" incident.

The attacker quietly disabled defenses, established persistent command-and-control, staged and exfiltrated data, moved laterally to the critical server, deployed ransomware, wiped backup copies, and attempted to cover their tracks with cleanup scripts.

**Compromised Hosts:** `as-pc2`, `AS-SRV`  
**Ransomware Group:** Akira  
**Key IOCs:** updater.exe, wsync.exe, st.exe, exfil_data.zip, clean.bat

## Attack Chain & MITRE ATT&CK Mapping

### Step 1-2: Ransom Note Analysis
The investigation began with the ransom note itself. Analysis quickly confirmed the threat actor as **Akira**, with the characteristic `akira_readme.txt` file and an onion address for negotiations.  
**MITRE ATT&CK:** T1486 – Data Encrypted for Impact

### Step 3-8: Infrastructure & Payload Staging
The attacker used `sync.cloud-endpoint.net` to host payloads and `cdn.cloud-endpoint.net` for additional C2 communications. Remote access was maintained through AnyDesk relays (`relay-0b975d23.net.anydesk.com`). Two primary C2 IPs were identified: `104.21.30.237` and `172.67.174.46`.  
**MITRE ATT&CK:** T1105 – Ingress Tool Transfer

![Q5 Payload Domain](https://github.com/user-attachments/assets/c427d9d1-5fe4-4a67-b130-2bd0fd956750)
![Q6 Domain Staged](https://github.com/user-attachments/assets/cfd6eb01-f20b-4bb6-8cb2-03c365180098)
![Q7 C2 IP Addresses](https://github.com/user-attachments/assets/ca3e5229-1671-429c-977b-e9ae16d7d1c1)
![Q8 Remote Relay](https://github.com/user-attachments/assets/e8b18a66-b9d7-4258-94d0-08b0552e47a8)

### Step 9-12: Defense Evasion & Credential Access
On `as-pc2`, the attacker executed the evasion script **kill.bat** (SHA256: `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`), tampered with the registry by setting `DisableAntiSpyware` to 1, and performed LSASS reconnaissance using `tasklist | findstr lsass`, followed by named pipe access to `\\Device\\NamedPipe\\lsass`.  
**MITRE ATT&CK:** T1562.001, T1112, T1003.001

![Q10 SHA256 Script](https://github.com/user-attachments/assets/b18833bc-4f41-4040-adbb-6642f84fd3d5)

### Step 13-18: Discovery & Lateral Movement
AnyDesk was deployed from the suspicious `C:\Users\Public\` directory for remote access. The compromised account `David.Mitchell` and external IP `88.97.164.155` were key. Lateral movement to `AS-SRV` was achieved using the privileged account `as.srv.administrator`.  
**MITRE ATT&CK:** T1135, T1021.001, T1078

![Q13 Process Hunt](https://github.com/user-attachments/assets/161a5a50-3b42-43ba-a9a3-2d6f9c075bd3)
![Q15 AnyDesk](https://github.com/user-attachments/assets/d04caad5-ce29-4d12-a6e6-3e6295f65e16)
![Q16 Suspicious Execution Path](https://github.com/user-attachments/assets/d0fab9f5-a378-4ee1-9e75-57081dc63a2d)
![Q17 Attacker IP](https://github.com/user-attachments/assets/62f63b64-9a40-4661-a344-259fdcbc3b29)

### Step 19-21: C2 Beacon
A new persistent beacon **wsync.exe** was deployed in `C:\ProgramData\` after the original beacon from "The Broker" became unstable.  
**MITRE ATT&CK:** T1543.003

![Q21 Beacon Hash](https://github.com/user-attachments/assets/95331085-a6b1-485a-a08d-b55cc4bb0a7f)

### Step 22-27: Scanner & Network Enumeration
The attacker ran the network scanner **scan.exe** with arguments `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us` (SHA256: `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`) and enumerated internal IPs `10.1.0.154` and `10.1.0.183`.  
**MITRE ATT&CK:** T1046, T1135

### Step 28-32: Download, Staging & Exfiltration
Tools were first downloaded using `bitsadmin.exe`, with `Invoke-WebRequest` as fallback. Data was then compressed using the staging tool **st.exe** (SHA256: `512a1f4ed9f512572608c729a2b89f44ea66a4`) into the archive **exfil_data.zip**.  
**MITRE ATT&CK:** T1105, T1560.001, T1041

### Step 33-38: Ransomware Deployment & Impact
The ransomware payload was disguised as **updater.exe** (SHA256: `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`). It was staged on `AS-SRV` via `powershell.exe`, shadow copies were deleted with `wmic shadowcopy delete`, and encryption began at **22:18:33 UTC** when `updater.exe` dropped the ransom note.  
**MITRE ATT&CK:** T1036.005, T1490, T1486

![Q37 Ransom Note Origin](https://github.com/user-attachments/assets/2ad81ef6-0db2-46b6-a736-6826f633e0d3)

### Step 39-40: Anti-Forensics & Scope
Post-encryption, the attacker ran **clean.bat** to delete the ransomware binary. The overall scope of the compromise was limited to `as-pc2` and `AS-SRV`.  
**MITRE ATT&CK:** T1070.004

## Evidence & Screenshots

All findings were validated through Advanced Hunting queries. The screenshots below provide visual evidence for each step (full set stored in the `/screenshots/` folder):

- **Step 1-2 (Ransom Note)**: Screenshot of `akira_readme.txt` with onion address.
- **Step 5-8 (Payload & C2 Infrastructure)**: DeviceNetworkEvents showing `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net`, and AnyDesk relays.
- **Step 9-12 (Evasion Script & Registry)**: DeviceFileEvents for `kill.bat` with SHA256 and registry tampering events.
- **Step 13-14 (LSASS Access)**: Process events showing `tasklist | findstr lsass` and named pipe `\\Device\\NamedPipe\\lsass`.
- **Step 15-18 (AnyDesk & Lateral Movement)**: AnyDesk execution in `C:\Users\Public\` and remote IPs.
- **Step 19-21 (Beacon)**: DeviceProcessEvents showing `wsync.exe` and beacon hash.
- **Step 23-27 (Scanner & Enumeration)**: Scanner execution and internal IP discovery.
- **Step 28-32 (Staging & Exfil)**: `st.exe`, `exfil_data.zip`, and download methods.
- **Step 33-38 (Ransomware Deployment)**: `updater.exe` execution, ransom note creation at 22:18:33 UTC, and shadow copy deletion.
- **Step 39-40 (Cleanup & Scope)**: `clean.bat` execution and affected hosts mapping.

## Key IOCs Summary

| Category                  | IOC                                      | Type     | Notes                              |
|---------------------------|------------------------------------------|----------|------------------------------------|
| Ransomware Filename       | updater.exe                              | File     | Masqueraded payload                |
| Ransomware Hash           | e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b | SHA256   | Akira encryptor                    |
| Staging Tool              | st.exe                                   | File     | Data compressor                    |
| Staging Tool Hash         | 512a1f4ed9f512572608c729a2b89f44ea66a4   | SHA256   | -                                  |
| Exfil Archive             | exfil_data.zip                           | File     | Final staged data                  |
| C2 Beacon                 | wsync.exe                                | File     | Persistence (C:\ProgramData\)      |
| Cleanup Script            | clean.bat                                | Script   | Post-ransomware cleanup            |
| Evasion Script            | kill.bat                                 | Script   | Early defense evasion              |
| Ransom Note               | akira_readme.txt                         | File     | Dropped by updater.exe             |
| C2 Domain                 | sync.cloud-endpoint.net                  | Domain   | Payload staging                    |
| Recovery Prevention       | wmic shadowcopy delete                   | Command  | Shadow copy deletion               |

## Lessons Learned & Recommendations

- Monitor unsigned binaries dropped in `%ProgramData%` and `%Public%`.
- Create detections for shadow copy deletion commands and suspicious `.bat` files.
- Enforce application allowlisting on servers.
- Keep tamper protection and behavioral blocking enabled in Microsoft Defender.
- Proactively hunt for masqueraded executables and LOLBIN abuse.

## Conclusion

This hands-on threat hunt successfully unraveled the complete Akira ransomware attack chain — from early evasion and persistence to data theft, encryption, and cleanup. By combining meticulous KQL hunting with real-world Akira TTP knowledge, the scope was clearly defined and the attack narrative reconstructed.

**Hunt Status:** Completed Successfully

---

**Created by:** Isaias Molina  
**Portfolio Project:** Advanced Threat Hunting Lab – Ashford Sterling Recruitment (Akira Ransomware)
