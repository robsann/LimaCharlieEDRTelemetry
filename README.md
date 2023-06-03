## LimaCharlie (EDR) Telemetry
- Windows 11 (Target) with Virus & Threat Prodection disabled, Sysmon and LimaCharlie (EDR) Sensor installed.
- Ubuntu Server (Attack) with Sliver, a Command & Control (C2) framework by BishopFox.
- Generate C2 payload, execute payload from Target machine, and start C2 session.
- Create Detection & Response Rules in LimaCharlie (EDR) to detect:
    - LSASS access
    - Shadow copies deletion using vssadmin.exe
