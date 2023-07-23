---
title: 'THM - Conti'
layout: single
author_profile: true
permalink: /writeups/conti
excerpt: 'Writeup for TryHackMe Conti Room'
toc: true
toc_sticky: true
toc_label: Challenges
---
## About
A writeup for a TryHackMe room [**Conti**](https://tryhackme.com/room/contiransomwarehgh) completed on 23 July 2023.

## Scenario

Some employees from your company reported that they can’t log into Outlook. The Exchange system admin also reported that he can’t log in to the Exchange Admin Center. After initial triage, they discovered some weird readme files settled on the Exchange server.

Below is a copy of the ransomware note.

![ransomnote](/assets/images/thmconti/conti_1.png)

Below are the error messages that the Exchange admin and employees see when they try to access anything related to Exchange or Outlook.

**Exchange Control Panel**:

![exchangepanel](/assets/images/thmconti/conti_2.png)

**Outlook Web Access**:

![webacess](/assets/images/thmconti/conti_3.png)

**Task**: You are assigned to investigate this situation. Use Splunk to answer the questions below regarding the Conti ransomware.

### Gathering log information

Using `index=”main”` and setting to “**all time**” for the date range shows 28145 events in splunk.

![Untitled](/assets/images/thmconti/conti_4.png)

Looking at the Users field, I see different users that are logged.

![Untitled](/assets/images/thmconti/conti_5.png)

Finally, from sourcetype, logs ingested are from **WinEventLog**, **Sysmon** and **IIS**.

![Untitled](/assets/images/thmconti/conti_6.png)

### Can you identify the location of the ransomware?

To start my search, I used the following filter to filter for and create a table to see all Image in Splunk. **EventCode=1** denotes process creation in Sysmon. I decided to filter for this event code as the ransomware has successfully run, and so using this filter will potentially show me where the ransomware is located. 

```
index="main" EventCode=1
| table Image 
| dedup Image
```

![Untitled](/assets/images/thmconti/conti_7.png)

However, there are many Image fields which contain “Splunk” which is not what I am looking for. Thus, I updated the filter to the one below to remove all the log entries that I am not interested in.

```
index="main" EventCode=1 NOT "Splunk"
| table Image 
| dedup Image
```

In the image below, I see a row with `C:\Users\Administrator\Documents\cmd.exe`. The typical location of `cmd.exe` will be at `C:\Windows\System32\cmd.exe`. `C:\Windows\System32\cmd.exe` also appears and having two exe with the same name is suspicious. 

![Untitled](/assets/images/thmconti/conti_8.png)

`C:\Users\Administrator\Documents\cmd.exe` is most likely masquarading as a legitimate Windows exe `cmd.exe` , which makes it suspicious and may be the ransomware.

Digging further using the filter below, I manage to find more suspicious events from `C:\Users\Administrator\Documents\cmd.exe`. **EventCode=11** is used to filter for file creation events.

```
index="main" EventCode=11 "C:\\Users\\Administrator\\Documents\\cmd.exe" 
| table Image TargetFilename
```

`C:\Users\Administrator\Documents\cmd.exe` created multiple `readme.txt` in different folders, and this `readme.txt` likely shows the ransom note from the scenario. Whats more interesting in the following image is that we see an Image `C:\Windows\system32\wbem\unsecapp.exe` creating `C:\Users\Administrator\Documents\cmd.exe`. 

`C:\Windows\system32\wbem\unsecapp.exe` is a legitimate Windows exe. From this [blog](https://helpdeskgeek.com/windows-10/what-is-unsecapp-exe-and-is-it-safe/), unsecapp stands for **Universal Sink to Receive Callbacks from Applications**, and is needed for Windows to receive and responds to requests from other applications. 

![Untitled](/assets/images/thmconti/conti_9.png)

**Answer:** `C:\Users\Administrator\Documents\cmd.exe`

### What is the Sysmon event ID for the related file creation event?

Sysmon **EventCode=11** denotes file creation events.

**Answer:** 11

### Can you find the MD5 hash of the ransomware?

Knowing the location of the ransomware, I used it to further refine my filter to search for events that logged this file. Additionally, I searched for events where the Hashes field is not empty.

```
index="main" "C:\\Users\\Administrator\\Documents\\cmd.exe" Hashes=*
```

The following image shows the log entry, which includes the MD5 hash.

![Untitled](/assets/images/thmconti/conti_10.png)

Searching for the hash on VirusTotal also points to the file being malicious.

![Untitled](/assets/images/thmconti/conti_11.png)

**Answer:** 290C7DFB01E50CEA9E19DA81A781AF2C

### What file was saved to multiple folder locations?

Looking through the table created with the filter below, I saw multiple `readme.txt` files being created in different folders.

```
index="main" EventCode=11 "C:\\Users\\Administrator\\Documents\\cmd.exe" 
| table Image TargetFilename
```

![Untitled](/assets/images/thmconti/conti_12.png)

**Answer:** readme.txt

### What was the command the attacker used to add a new user to the compromised system?

Looking at the ComputerName field using the below filter, I know the name of the compromised system is `WIN-AOQKG2AS2Q7.bellybear.local` .

```
index="main" "C:\\Users\\Administrator\\Documents\\cmd.exe" 
```

![Untitled](/assets/images/thmconti/conti_13.png)

Changing the filter to the one shown below shows a log entry where a user account “securityninja” is created. **EventCode=4720** is used as it denotes new user account being created in Sysmon.

```
index="main" ComputerName="WIN-AOQKG2AS2Q7.bellybear.local" EventCode=4720
```

![Untitled](/assets/images/thmconti/conti_14.png)

I know that a user account “securityninja” is created, thus I changed my filter to the following.

```
index="main" "securityninja"
```

Looking at the CommandLine field, I can see the command used to create the new user.

![Untitled](/assets/images/thmconti/conti_15.png)

**Answer:** `net user /add securityninja hardToHack123$`

### The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?

I googled for the event code sysmon used for process migration on Google using the following search term “sysmon migrated process event code”. The [first link](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008) showed that Sysmon logs this event as **EventCode=8**.

I changed my filter to the following.

```
index="main" EventCode=8
```

Two log entries are returned. The screenshot below shows the first log entry and the migrated process as `C:\Windows\System32\lsass.exe` and the original process is `C:\Windows\System32\wbem\unsecapp.exe`.

![Untitled](/assets/images/thmconti/conti_16.png)

Looking at the second log entry, the migrated process is `C:\Windows\System32\wbem\unsecapp.exe` and the original process is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

![Untitled](/assets/images/thmconti/conti_17.png)

As the question is asking for the original process image when the attacker got on the system, the more likely answer is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\wbem\unsecapp.exe` and not `C:\Windows\System32\wbem\unsecapp.exe;C:\Windows\System32\lsass.exe`. 

`C:\Windows\System32\wbem\unsecapp.exe;C:\Windows\System32\lsass.exe` is possibly used as a process migration for later stages.

**Answer:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\wbem\unsecapp.exe`

### The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?

Local Security Authority Server Service (LSASS) credential dumping is a common TTP in recovering password hashes. LSASS is a process in Windows responsible for enforcing security policies on system. LSASS is responsible for verifying user logins into Windows, handling password changes, and creating access tokens. 

Recovering a dump of LSASS will allow adversaries to conduct further pivoting into the network using pass-the-hash attack. This [blog](https://juggernaut-sec.com/dumping-credentials-lsass-process-hashes/) is a great reference for LSASS credential dumping.

Using the same filter as the above question, and looking at the first log entry shows a process migration from `C:\Windows\System32\wbem\unsecapp.exe` to `C:\Windows\System32\lsass.exe` .

```
index="main" EventCode=8
```

![Untitled](/assets/images/thmconti/conti_16.png)

**Answer:** `C:\Windows\System32\lsass.exe` 

### What is the web shell the exploit deployed to the system?

IIS are Exchange logs and these logs are also ingested into Splunk. I thus constructed the following filter to only see IIS logs.

```
index="main" sourcetype="iis"
```

Looking at the **s_ip** field, I can see four different values logged. **s_ip** is the IP address of the server where the log entry is generated. In this case, **s_ip** will denote the exchange web server. I guess the server address will most likely be 10[.]10[.]10[.]6. 

![Untitled](/assets/images/thmconti/conti_18.png)

In order to further reduce the number of events seen I added the filter for **s_ip** to show only 10[.]10[.]10[.]6. 

```
index="main" sourcetype="iis" s_ip="10.10.10.6"
```

Looking at the **cs_uri_stem** field, I see the following values.

![Untitled](/assets/images/thmconti/conti_19.png)

`/ecp/default.aspx` and `/owa/auth/logon.aspx` are seen in the images under the scenario section. I also noticed `/owa/auth/i3gfPctK1c2x.aspx` which seems to be suspicious. Using this filter,

```
index="main" sourcetype="iis" s_ip="10.10.10.6" cs_uri_stem="/owa/auth/i3gfPctK1c2x.aspx"
```

I noticed in the first log entry the **c_ip** is listed as 10[.]10[.]10[.]2. For IIS logs, c_ip denotes the IP address of the client that made the request.

![Untitled](/assets/images/thmconti/conti_20.png)

I wanted to confirm that 10[.]10[.]10[.]6 belongs to `WIN-AOQKG2AS2Q7.bellybear.local` which we know is compromised. Thus, I used the following filter to create the table shown below. 

```
index="main" "WIN-AOQKG2AS2Q7.bellybear.local" "10.10.10.6" "10.10.10.2"
| table SourceIp SourceHostname DestinationIp DestinationHostname
```

From the table below, the SourceHostname field shows `WIN-AOQKG2AS2Q7.bellybear.local` while the SourceIp is 10[.]10[.]10[.]6. Therefore, I can conclude that `WIN-AOQKG2AS2Q7.bellybear.local` has the IP address of 10[.]10[.]10[.]6 while the adversary IP address is 10[.]10[.]10[.]2.

![Untitled](/assets/images/thmconti/conti_21.png)

**Answer:** `i3gfPctK1c2x.aspx`

### What is the command line that executed this web shell?

I know that the web shell is `i3gfPctK1c2x.aspx` and thus, I used this as part of the filter and also searched for **EventCode=1** which stands for process creation. 

```
index="main" "i3gfPctK1c2x.aspx" EventCode=1
```

There is only one log entry returned, which contains the command line that executed the web shell.

![Untitled](/assets/images/thmconti/conti_22.png)

**Answer:** `attrib.exe -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx`

### What three CVEs did this exploit leverage?

This [blog](https://www.securin.io/is-conti-ransomware-on-a-roll/) talks about the three vulnerabilities associated with Conti. From national vulnerability database (NVD) these three vulnerabilities are:

**CVE-2020-0796**

![Untitled](/assets/images/thmconti/conti_23.png)

**CVE-2018-13374**

![Untitled](/assets/images/thmconti/conti_24.png)

**CVE-2018-13379**

![Untitled](/assets/images/thmconti/conti_25.png)

**Answer:** CVE-2020-0796, CVE-2018-13374, CVE-2018-13379
