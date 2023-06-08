# LimaCharlie (EDR) Telemetry

## Overview
- Windows 11 (Target) with Virus & Threat Prodection disabled, Sysmon and LimaCharlie (EDR) Sensor installed.
- Ubuntu Server (Attack) with Sliver, a Command & Control (C2) framework by BishopFox, installed.
- Generate C2 payload using Sliver, execute payload from Target machine, and start C2 session on Sliver.
- Use C2 session to perform two attacks on Target Machine:
    - LSASS access (credentials stealing)
    - Shadow Copies deletion using vssadmin.exe (used in Ransomware attacks).
- Create Detection & Response rules in LimaCharlie (EDR) to detect the two previous attacks using
the telemetry generated by them and test the rules by performing the attacks again.

The procedures to build this Lab can be found [here](https://github.com/robsann/LimaCharlieEDRTelemetry/blob/main/procedure.md) and it was adapted from [Eric Capuano](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro).

## Diagram

# Highlights

## 1 - Pre Setup

### 1.1 - VirtualBox NAT Network with Port Forwarding configuration
<img src="images/0a-virtualbox_nat_network.png" title="NAT Network"/>

### 1.2 - Network configuration of Ubuntu Server (10.0.2.4) and Windows 11 (10.0.2.5)
<img src="images/0b-network_config.png" title="Network Configuration"/>

### 1.3 - Windows 11 Virus & threat protection disabled
<img src="images/0c-win_security_disabled.png" title="Windows Security Disabled"/>

### 1.4 - Windows 11 Sysmon events
<img src="images/0d-sysmon_events.png" title="Sysmon Events"/>

## 2 - Payload generation and C2 session establishment

### 2.1 - Payload generation on Sliver on the Attack Machine
<img src="images/1-sliver_payload_gen.png" title="Payload Generation"/>

### 2.2 - LimaCharlied Timeline event of the payload download on Windows Machine
<img src="images/2a-LC_win_payload_download.png" title="Payload Download"/>

### 2.3 - LimaCharlied Timeline event of the payload execution on Windows Machine
<img src="images/2b-LC_win_payload_exec.png" title="Payload Execution"/>

### 2.4 - LimaCharlied Timeline event of the payload connection to the Sliver C2
<img src="images/2c-LC_payload_connect_to_C2.png" title="Payload Connection"/>

### 2.5 - Sliver C2 session on Attack Machine
<img src="images/3-sliver_session.png" title="Sliver C2 Session"/>

### 2.6 - LimaCharlie Processes showing the processes running on the Windows Machine including the payload `CURLY_DRAWER.exe`
<img src="images/4-LC_processes.png" title="Windows Processes"/>

## 3 - LSASS Access event, rule creation, and detection

### 3.1 - LimaCharlie Timeline showing LSASS access event
<img src="images/5a-LC_lsass_access_event.png" title="LSASS Access Event"/>

### 3.2 - LimaCharlie Custom Detect & Respond Rule for LSASS Access
<img src="images/5b-LC_lsass_access_rule.png" title="LSASS Access Rule"/>

### 3.3 - LimaCharlie Detections showing LSASS access detected by custom rule created
<img src="images/5c-LC_lsass_access_detected.png" title="LSASS Access Detected"/>

## 4 - Shadows Copies deletion event, rule creation, and detection

### 4.1 - LimaCharlie Timeline showing delete Shadows Copies event
<img src="images/6a-LC_delete_shadows_event.png" title="Delete Shadows Copie Event"/>

### 4.2 - LimaCharlie Custom Detect & Respond Rule for delete Shadows Copies
<img src="images/6b-LC_delete_shadows_rule.png" title="Delete Shadows Copie Rule"/>

### 4.3 - LimaCharlie Detections showing delete Shadows Copies detected by custom rule created
<img src="images/6c-LC_delete_shadows_detected.png" title="Delete Shadows Copie Detected"/>

## 5 - Rules pre-loaded on LimaCharlie

### 5.1 - LimaCharlie Detections showing Sigma rule at category Non Interactive PowerShell Process Spawned
- Author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
- Description: Detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent."
<img src="images/7a-LC_non_interactive_powershell_detected.png" title="Non Interactive Powershell Detected"/>

### 5.2 - LimaCharlie Detections showing rule from the category HackTool - Sliver C2 Implant Acrivity Pattern
- Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
- Description: Detects process activity patterns as seen being used by Sliver C2 framework implants.
<img src="images/7b-LC_sliver_C2_implant_activity_detected.png" title="Sliver C2 Implant Activity Detected"/>

### 5.3 - LimaCharlie Detections showing rule from the category Silver Shell
- Author: Trenton Tait.
- Description: Detects the powershell command used when a Sliver agent creates an interactive shell with its built in shell command.
<img src="images/7c-LC_sliver_shell_detected.png" title="Sliver C2 Shell Detected"/>

### 5.4 - LimaCharlie Detections showing Sigma rule from the category Shadow Copies Deletion Using Operating System Utilities
- Author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades).
- Description: Shadow Copies deletion using operating systems utilities.
<img src="images/7d-LC_shadow_copies_deletion_detected.png" title="Shadow Copies Deletion Detected"/>

