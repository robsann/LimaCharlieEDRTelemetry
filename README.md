# LimaCharlie (EDR) Telemetry

## Overview
- Configured in VirtualBox:
    - Windows 11 (Target) with Virus & Threat Protection disabled, Sysmon and LimaCharlie (EDR) Sensor installed
    - Ubuntu Server (Attack) with Sliver installed, a Command & Control (C2) framework by BishopFox.
- Generated C2 payload on Attack Machine, executed the payload on Target Machine, and started C2 session on Attack Machine.
- Used C2 session to perform two attacks on Target Machine:
    - LSASS access (credentials stealing).
    - Shadow Copies deletion using vssadmin.exe (used in Ransomware attacks).
- Created Detection & Response Rules in LimaCharlie (EDR) to detect the two previous attacks using the telemetry generated and tested the rules by repeating the attacks.

The procedures to build this Lab can be found [here](https://github.com/robsann/LimaCharlieEDRTelemetry/blob/main/procedure.md), and it was adapted from [Eric Capuano](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro).

## VirtualBox NAT Network Diagram
<img src="images/LimaCharlie_diagram.png" title="Virtual Network Diagram"/>

### NAT Network
The configuration of the NAT Network used and the Port Forwarding Rule to access the Ubuntu Server through SSH from the host. In the NAT Network the virtual machines can communicate with each other and the host and have access to the Internet, while the host can communicate with the virtual machines only through port forwarding.


<img src="images/1.1-virtualbox_nat_network.png" title="NAT Network"/>

### IP Addresses
<img src="images/1.2-network_config.png" title="Network Configuration"/>


# Highlights

## 1 - Windows 11 Setup

### 1.3 - Virus & threat protection disabled
The Antivirus was disabled to be able to download and execute the payload to stablishes the C2 session with Sliver.

<img src="images/1.3-win_security_disabled.png" title="Windows Security Disabled"/>

### 1.4 - Sysmon events
The Sysmon was installed to increase the telemtry gathered by LimaCharlie.

<img src="images/1.4-sysmon_events.png" title="Sysmon Events"/>

## 2 - Payload Generation and C2 Session

### 2.1 - Payload generation
The payload was generated on Sliver on the Attack Machine and it has the name `CURLY_DRAWER.exe` and it is configured to try to connect to the Attack Machine when executed on the Target Machine.

<img src="images/2.1-sliver_payload_gen.png" title="Payload Generation"/>

### 2.2 - LimaCharlied timeline payload donload event
On the Timeline section on LimaCharlie it is shown the event of the payload download on the Target Machine.

<img src="images/2.2-LC_win_payload_download.png" title="Payload Download"/>

### 2.3 - LimaCharlied timeline payload execution event
On the Timeline section on LimaCharlie it is shown the event of the payload execution on the Target Machine.

<img src="images/2.3-LC_win_payload_exec.png" title="Payload Execution"/>

### 2.4 - LimaCharlied Timeline event of the payload connection to the Sliver C2
On the Timeline section on LimaCharlie it is shown the event of the payload connection from the Target Machine to the Sliver C2 on the Attack Machine.

<img src="images/2.4-LC_payload_connect_to_C2.png" title="Payload Connection"/>

### 2.5 - Sliver C2 session
The C2 session open in Sliver on the Attack Machine and gathering some information from the Target Machine
.
<img src="images/2.5-sliver_session.png" title="Sliver C2 Session"/>

### 2.6 - LimaCharlie processes table
On the Processes section on LimaCharlie it can be seen the processes running on the Target Machine including the payload `CURLY_DRAWER.exe` executed on PowerShell, with information about the network connection stablished.

<img src="images/2.6-LC_processes.png" title="Windows Processes"/>

## 3 - LSASS Access Attack (Credential Stealing)

### 3.1 - LSASS Access Event

<img src="images/3.1-LC_lsass_access_event.png" title="LSASS Access Event"/>

### 3.2 - LSASS Access Custom Detect & Respond Rule

<img src="images/3.2-LC_lsass_access_rule.png" title="LSASS Access Rule"/>

### 3.3 - LSASS Access Detection
LimaCharlie Detections showing LSASS access detected by custom rule created.

<img src="images/3.3-LC_lsass_access_detected.png" title="LSASS Access Detected"/>

## 4 - Shadows Copies Deletion Attack

### 4.1 - Shadows Copies Deletion Event

<img src="images/4.1-LC_delete_shadows_event.png" title="Delete Shadows Copie Event"/>

### 4.2 - Shadows Copies Deletion Custom Detect & Respond Rule

<img src="images/4.2-LC_delete_shadows_rule.png" title="Delete Shadows Copie Rule"/>

### 4.3 - Shadows Copies Deletion Detection
LimaCharlie Detections showing delete Shadows Copies detected by custom rule created.

<img src="images/4.3-LC_delete_shadows_detected.png" title="Delete Shadows Copie Detected"/>

## 5 - Pre-Loaded Rules Triggered by Sliver C2 Activity

### 5.1 - Sigma Rule at Category Non Interactive PowerShell Process Spawned
This rule was developed by Roberto Rodriguez @Cyb3rWard0g (rule) and oscd.community (improvements). It detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent or "CURLY_DRAWER.exe" in this case.

<img src="images/5.1-LC_non_interactive_powershell_detected.png" title="Non Interactive Powershell Detected"/>

### 5.2 - Rule from the Category HackTool - Sliver C2 Implant Acrivity Pattern
This rule was developed by Nasreddine Bencherchali (Nextron Systems) and Florian Roth (Nextron Systems). It detects process activity patterns as seen being used by Sliver C2 framework implants.

<img src="images/5.2-LC_sliver_C2_implant_activity_detected.png" title="Sliver C2 Implant Activity Detected"/>

### 5.3 - Rule from the Category Silver Shell
This rule was developed by Trenton Tait. It detects the powershell command used when a Sliver agent creates an interactive shell with its built in shell command.

<img src="images/5.3-LC_sliver_shell_detected.png" title="Sliver C2 Shell Detected"/>

### 5.4 - Sigma Rule from the Category Shadow Copies Deletion Using Operating System Utilities
This rule was developed by Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, Andreas Hunkeler (@Karneades), and oscd.community. It detects Shadow Copies deletion using operating systems utilities.

<img src="images/5.4-LC_shadow_copies_deletion_detected.png" title="Shadow Copies Deletion Detected"/>

