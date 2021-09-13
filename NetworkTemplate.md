# Network Forensic Analysis Report

## Setup

For This Part of the Project, live traffic within the intranet was captured through wireshark.
- For the purpose of this project,command `systemctl start sniff` was ran which uses `tcpreplay` to replay PCAPs in `/opt/pcaps` onto Kali's `eth0` interface.
- This was then captured for about 15min through wireshark as live traffic.
- Once the live traffic was all captured, command `systemctl stop sniff` was ran to stop the `tcpreply`.
- Then, this capture was saved to a file.

<br>
<br>

## Time Thieves 

You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site?
    - frank-n-ted.com
    ![Time_Thieves_1.1](Images/Network/TimeThieves-1.1.png)
    - You can also find their name within DHCP packet
    ![Time_Thieves_1.2](Images/Network/TimeThieves-1.2.png)

2. What is the IP address of the Domain Controller (DC) of the AD network?
    - 10.6.12.157
3. What is the name of the malware downloaded to the 10.6.12.203 machine?
    - june11.dll
    ![Time_Thieves_3.1](Images/Network/TimeThieves-3.1.png)
   - Once you have found the file, export it to your Kali machine's desktop.
   - You can download the actual malware file by going to `File > Export Objects > HTTP`
    ![Time_Thieves_3.2](Images/Network/TimeThieves-3.2.png)
4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/). 
    - ![VirusTotal](Images/Network/VirusTotal.png)
5. What kind of malware is this classified as?
    - Trojan Horse

<br>
<br>

---

## Vulnerable Windows Machine

1. Find the following information about the infected Windows machine:
    - Host name: ROTTERDAM-PC
    ![Vulnerable-1.1](Images/Network/Vulnerable-1.1.png)
    - IP address: 172.16.4.205
    ![Vulnerable-1.2](Images/Network/Vulnerable-1.2.png)
    - MAC address: 00:59:07:b0:63:a4
    ![Vulnerable-1.3](Images/Network/Vulnerable-1.3.png)
    
2. What is the username of the Windows user whose computer is infected?
    - matthijs.devries
    - Note that for CNameString values for hostnames always end with a $ (dollar sign), while user account names do not.
    ![Vulnerable-2.1](Images/Network/Vulnerable-2.1.png)
3. What are the IP addresses used in the actual infection traffic?
    - 182.243.115.84
    - For this, you can use `Statistics > Conversation` then, look at the TCP tab.
    - You would look at the most amount of Bytes that the infected windows was communicating to.
    ![Vulnerable-3.1](Images/Network/Vulnerable-3.1.png)
    - You can also confirm this by looking at the TCP stream. The body of this TCP stream is not clear indicating that it could be infected.
    ![Vulnerable-3.2](Images/Network/Vulnerable-3.2.png)
4. As a bonus, retrieve the desktop background of the Windows host.
    - For this, you would go to `File > Export Objects > HTTP`
    - The Size of the img is quite large compared to the other image files.
    - In this case, the size of the file can indicate that it's a desktop image, as Desktop Background images are usually high in resolution.
    ![Vulnerable-4.1](Images/Network/Vulnerable-4.1.png)
    - Once downloaded, you can also look at the property of the file to confirm. 
    - You can see that Image size is 1920x1080 pixels, which is the size that is likely used for desktop images.
    ![Vulnerable-4.2](Images/Network/Vulnerable-4.2.png)
    - Here is the downloaded Deskbop background image:
    ![Vulnerable-4.3](Images/Network/Vulnerable-4.3.png)

<br>
<br>

---

## Illegal Downloads

1. Find the following information about the machine with IP address `10.0.0.201`:
    - MAC address: 00:16:17:18:66:c8
    - Windows username: elmer.blanco
    ![Illegal-1.1](Images/Network/Illegal-1.1.png)
    ![Illegal-1.2](Images/Network/Illegal-1.2.png)
    - OS version: Windows NT 10.0; Win64; x64 (Windows 10)
    - For OS version, I've searched for TCP stream in HTTP
    ![Illegal-1.3](Images/Network/Illegal-1.3.png)

2. Which torrent file did the user download?
    - Betty_Boop_Rhythm_on_the_Reservation.avi.torrent
    ![Illegal-2.1](Images/Network/Illegal-2.1.png)



<br>
<br>
<br>


### <u> Author </u>
My name is [Sooji Lee](https://www.linkedin.com/in/soojilee88/) :)