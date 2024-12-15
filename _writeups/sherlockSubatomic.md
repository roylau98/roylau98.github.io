---
title: 'HTB - Sherlock (Subatomic)'
layout: single
author_profile: true
permalink: /writeups/sherlockSubatomic
excerpt: 'Writeup for HackTheBox Subatomic (Sherlock)'
toc: true
toc_sticky: true
toc_label: Questions
---
## About
A writeup for a HackTheBox [**Subatomic (Sherlock)**](https://app.hackthebox.com/sherlocks/Subatomic/play) completed on 15 December 2024.

![Untitled](/assets/images/htbsherlock/subatomic/completed.png)

## Scenario

Forela is in need of your assistance. They were informed by an employee that their Discord account had been used to send a message with a link to a file they suspect is malware. The message read: "Hi! I've been working on a new game I think you may be interested in it. It combines a number of games we like to play together, check it out!". The Forela user has tried to secure their Discord account, but somehow the messages keep being sent and they need your help to understand this malware and regain control of their account! Warning: This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.

A single zip file (subatomic.zip, MD5: 856086a2356e559ac310a2202cd64252) was given.
## Task

### What is the Imphash of this malware installer?

We can use PE-bear to get the imphash of the malware installer.

![Untitled](/assets/images/htbsherlock/subatomic/imphash.png)

**Answer**: b34f154ec913d2d2c435cbd644e91687

### The malware contains a digital signature. What is the program name specified in the SpcSpOpusInfo Data Structure?

We can view the malware installer properties to identify the program name in the digital signature.

![Untitled](/assets/images/htbsherlock/subatomic/programname.png)

**Answer**: Windows Update Assistant

Note that we can extract the installer (nsis-installer.exe) using 7z. This results in the following files.

![Untitled](/assets/images/htbsherlock/subatomic/7z.png)

### The malware uses a unique GUID during installation, what is this GUID?

Looking at the [NSIS].nsi installation script, there are some UID present.

![Untitled](/assets/images/htbsherlock/subatomic/guid.png)

**Answer**: cfbc383d-9aa0-5771-9485-7b806e8442d5

Within $PLUGINSDIR we find app-32.7z which we can similarly extract using 7z.

![Untitled](/assets/images/htbsherlock/subatomic/7z2.png)

### The malware contains a package.json file with metadata associated with it. What is the 'License' tied to this malware?

Unzip app-32.7z, and within the folder contains the resources directory. Inside it contains the app.asar which is the package.json file.

![Untitled](/assets/images/htbsherlock/subatomic/isc.png)

**Answer**: ISC

### The malware connects back to a C2 address during execution. What is the domain used for C2?

We can now perform dynamic analysis to learn more about the functionality of the installer. We first run fakenet to understand what domains the malware connects back to, and recover the C2 address.

![Untitled](/assets/images/htbsherlock/subatomic/c2.png)

**Answer**: illitmagnetic[.]site

Dynamic analysis only allow us to answer the questions up to this point. Thus, we move to static analysis to better understand the malware. 

We then move to the resources directory where we find app.asar which can be extracted using asar. Note that this requires asar to be installed in the machine which is possible using `npm install -g asar`. Therefore we recover the javascript used to realise the malicious functionalities.

![Untitled](/assets/images/htbsherlock/subatomic/final.png)

The javascript is highly obfuscated thus we rely on debugging the code. This may potentially allow deobfuscation of the code and we do not have to manually deobfuscate the code which can take a long time. 

![Untitled](/assets/images/htbsherlock/subatomic/js.png)

Note that there may be issues running the code which could be fixed by running the following commands to remove and install the needed libraries. We can now start to debug the code.

```cmd
del .\node_modules\@primno
npm install @primno/dpapi

del .\node_modules\sqlite3\
npm install sqlite3
```

Debugging the code in Visual Studio allow us to see the deobfuscated code. We can now perform static analysis and understand the malicious code.

![Untitled](/assets/images/htbsherlock/subatomic/deobfuscated.png)

### The malware attempts to get the public IP address of an infected system. What is the full URL used to retrieve this information?

Searching the code shows this function newInjection(). It retrives the public IP address using ipinfo[.]io and use it to construct a JSON object.

![Untitled](/assets/images/htbsherlock/subatomic/ip.png)

**Answer**: https[://]ipinfo[.]io/json

### The malware is looking for a particular path to connect back on. What is the full URL used for C2 of this malware?

Based on the previous image we can see that it uses fetch to send a post request to `options.api + new-injection`. Thus we can find the object options which will include the URL.

![Untitled](/assets/images/htbsherlock/subatomic/full.png)

**Answer**: https[://]illitmagnetic[.]site/api/

### The malware has a configured user_id which is sent to the C2 in the headers or body on every request. What is the key or variable name sent which contains the user_id value?

We can search for user_id to look for references in the code. This led us to the headers which are sent as part of the request. 

![Untitled](/assets/images/htbsherlock/subatomic/userkey.png)

**Answer**: duvet_user

### The malware checks for a number of hostnames upon execution, and if any are found it will terminate. What hostname is it looking for that begins with arch?

We can similarly search for `arch` to look for references in the code which will lead us to the hostnames.

![Untitled](/assets/images/htbsherlock/subatomic/hostname.png)

**Answer**: archibaldpc

### The malware looks for a number of processes when checking if it is running in a VM; however, the malware author has mistakenly made it check for the same process twice. What is the name of this process?

Analysing the same checkVm() function will show the process that was checked twice.

![Untitled](/assets/images/htbsherlock/subatomic/processes.png)

**Answer**: vmwaretray

### The malware has a special function which checks to see if C:\Windows\system32\cmd.exe exists. If it doesn't it will write a file from the C2 server to an unusual location on disk using the environment variable USERPROFILE. What is the location it will be written to?

We can search for references to `cmd` which leads us to the checkCmdInstallation() function. We note that there is a join() which takes in process.env.USERPROFILE, 'Documents' and 'cmd.exe'. 

![Untitled](/assets/images/htbsherlock/subatomic/cmd.png)

**Answer**: %USERPROFILE%\Documents\cmd.exe

### The malware appears to be targeting browsers as much as Discord. What command is run to locate Firefox cookies on the system?

Looking for references to `Firefox` shows the function getFirefoxCookies(). This function is responsible for locating Firefox cookies on the system. 

![Untitled](/assets/images/htbsherlock/subatomic/cookies.png)

**Answer**: where /r . cookies.sqlite

### To finally eradicate the malware, Forela needs you to find out what Discord module has been modified by the malware so they can clean it up. What is the Discord module infected by this malware, and what's the name of the infected file?

Finally, we can search for references to `discord` which leads us to discordInjection(). We can see that it tries to infect the module discord_desktop_core-1, and edit index.js using data from the C2.

![Untitled](/assets/images/htbsherlock/subatomic/infected.png)

**Answer**: discord_desktop_core-1, index.js