---
title: 'HTB - Sherlock (Lockpick3.0)'
layout: single
author_profile: true
permalink: /writeups/sherlockLockpick3
excerpt: 'Writeup for HackTheBox Lockpick3.0 (Sherlock)'
toc: true
toc_sticky: true
toc_label: Questions
---
## About
A writeup for a HackTheBox [**Lockpick3.0 (Sherlock)**](https://app.hackthebox.com/sherlocks/Lockpick3.0) completed on 19 December 2024.

![Untitled](/assets/images/htbsherlock/lockpick3/completed.png)

## Scenario

The threat actors of the Lockpick variant of Ransomware seem to have increased their skillset. Thankfully on this occasion they only hit a development, non production server. We require your assistance performing some reverse engineering of the payload in addition to some analysis of some relevant artifacts. Interestingly we can't find evidence of remote access so there is likely an insider threat.... Good luck! Please note on the day of release this is being utilised for a workshop, however will still be available (and free).

A single zip file (lockpick3.zip, MD5: dfe0dbcc99062c68b095357ee8f17bec) was given.
## Task

### Please confirm the file hash of the malware? (MD5)

We can use the command `certutil -hashfile <filename> md5` to compute the MD5 hash.

![Untitled](/assets/images/htbsherlock/lockpick3/md5.png)

**Answer**: a2444b61b65be96fc2e65924dee8febd

### Please confirm the XOR string utilised by the attacker for obfuscation?

We can use the strings utility to find the xor string within the *.vmem file. This is done by using the command `strings.exe -n 8 <file location> | findstr "ubuntu-client"`

![Untitled](/assets/images/htbsherlock/lockpick3/strings.png)

**Answer**: xGonnaGiveIt2Ya

### What is the API endpoint utilised to retrieve the key?

We can now start reversing `ubuntu-client` to understand what it does. Within the binary contains a function that accepts four arguments; an encrypted string, the encrypted string length, the xor key and the xor key length. The following shows the disassembled function. 

![Untitled](/assets/images/htbsherlock/lockpick3/enc.png)

The function just performs an xor operation with the key and the encrypted string. Thus we can write a simple script using Python to recover all the strings. We can start renaming the values in IDA after recovering the strings.

![Untitled](/assets/images/htbsherlock/lockpick3/dec.png)

The following script was used for decyption.

```python
def main():
    enclist = ["10331B1E1D5B68460609281A592D0E166A0E1E1E4C74181F02385A5D37051120061A0F0D280A1304275A53291157", "0B220D065C55", "5734070F1C0468", "57321C1C41032E0759102B015C2D1455351A", "57221B0D41123E1A020024101D2A180B330A034114251C18113C2B402C0F162E01094012221B000C2A11", "231201071A3C4D2D13162A065B2915112801533B0332070210692647370F112908642F07330C04582711462E0E0A2C411A0F13200C026F1227572B1711240A3364243F0C15363D15402D5C57321C1C41032E0759102B015C2D1455351A004E190006180B28335B2F0431335D370F6B150C0511280646640014300E171D6B121A131774065D3615721C26001D1526051A3843235337151D232D17530C3205020C6401413C1356330E1C090433", "0B3E1C1A0B0C241D1A452D1557340E166A1D0B020E260D56436F544120120C22020D1A0D670C18042B185779141A32011A1B3E351C180B201A5577121D3519070D04674F50453A0D412D0415241B024E12330804116901502C0F0C32301C1B0F290018026707572B1711240A"]
    key = b'xGonnaGiveIt2Ya'

    for enc in enclist:
        enc = bytes.fromhex(enc)
        dec = ""
        for i in range(len(enc)):
            dec += chr((enc[i] ^ key[i % len(key)]) & 0xFF)
        
        print(dec)

if __name__=='__main__':
    main()
```

Next, we can try to find references to the domain in the binary. Within one of the function we see that it tries to combine the domain and /connect using snprintf. 

![Untitled](/assets/images/htbsherlock/lockpick3/connect.png)

If we scroll down further we see that it uses `_curl_easy_perform` to perform a network transfer, then parses an JSON object using `_cJSON_Parse`. Finally it tries to get a `key` value using _cJSON_GetObjectItem. Thus, we can conclude that the API endpoint is /connect. This will retrieve the key, IV and client_id values.

![Untitled](/assets/images/htbsherlock/lockpick3/curl.png)

**Answer**: https[://]plankton-app-3qigq[.]ondigitalocean[.]app/connect

### What is the API endpoint utilised for upload of files?

There are two references to the decrypted domain in two different function. The first function is responsible for retrieving the key, while the other was used to upload files. 

We can see that it first tries to read a file using `_fopen`. 

![Untitled](/assets/images/htbsherlock/lockpick3/fopen.png)

Later on the function uses snprintf to combine the domain and string `/upload/`. Next, the function sets the appropriate options using libcurl and finally uploads the file using `_curl_easy_perform`.

![Untitled](/assets/images/htbsherlock/lockpick3/upload.png)

**Answer**: https[://]plankton-app-3qigq[.]ondigitalocean[.]app/upload/

### What is the name of the service created by the malware?

Looking at the decrypted string, we can see that the malware uses systemctl to start ubuntu_running.service. There is also a file named ubuntu_running.service in `/etc/systemd/system` directory which likely contains the service unit. Hence the name of the service is `ubuntu_running.service`.

![Untitled](/assets/images/htbsherlock/lockpick3/dec.png)

**Answer**: ubuntu_running.service

### What is the technique ID utilised by the attacker for persistence?

We can search MITRE ATT&CK to look for the technique ID for Systemd Service creation. 

![Untitled](/assets/images/htbsherlock/lockpick3/mitre.png)

**Answer**: T1543.002