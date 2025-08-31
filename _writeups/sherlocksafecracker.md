---
title: 'HTB - Sherlock (Safecracker)'
layout: single
author_profile: true
permalink: /writeups/sherlocksafecracker
excerpt: 'Writeup for HackTheBox Safecracker (Sherlock)'
toc: true
toc_sticky: true
toc_label: Questions
---
## About
A writeup for a HackTheBox [**Safecracker (Sherlock)**](https://app.hackthebox.com/sherlocks/Safecracker) completed on 31 Aug 2025:

![Untitled](/assets/images/htbsherlock/safecracker/completed.png)

## Scenario

We recently hired some contractors to continue the development of our Backup services hosted on a Windows server. We have provided the contractors with accounts for our domain. When our system administrator recently logged on, we found some pretty critical files encrypted and a note left by the attackers. We suspect we have been ransomwared. We want to understand how this attack happened via a full in-depth analysis of any malicious files out of our standard triage. A word of warning, our tooling didn't pick up any of the actions carried out - this could be advanced. Warning This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.

A single zip file (safecracker.zip, MD5: 61ea7f259763c0937bee773a16f4ce84) was given.

## Task

### Which user account was utilised for initial access to our company server?

Files found within the zip file (safecracker.zip) was loaded into autopsy for analysis which allowed us to answer some of the following questions. 

After loading the files, we can go to the OS Accounts tab which shows the users account on the machine. We can see an account `safecracker01` which is likely the beachhead host.

![Untitled](/assets/images/htbsherlock/safecracker/accounts.png)

**Answer**: contractor01

### Which command did the TA utilise to escalate to SYSTEM after the initial compromise?

A file named ConsoleHost_history.txt contains the commands that the TA executes on the system. This file is usually found in `C:\Users\__username__\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\` and contains a record of commands executed in Powershell.

![Untitled](/assets/images/htbsherlock/safecracker/command.png)

**Answer**: .\PsExec64.exe -s -i cmd.exe

### How many files have been encrypted by the the ransomware deployment?

To answer this question, we have to first determine the file extension that the ransomware used to mark encrypted files. If we look at `C:\Users\Administrator\Downloads`, we can see that Autopsy marked an executable (`MsMpEng.exe`) as suspicious. 

Two other files were present `Sysmon.zip.31337` and `Sysmon.zip.note` which is likely the encrypted file and ransom note.

![Untitled](/assets/images/htbsherlock/safecracker/admindownloads.png)

Since we know that encrypted files have the extension `.31337`, I opted to use the $MFT to get the number of files encrypted. Using `MFTECmd` and `Timeline Explorer`, the number of encrypted files was 33.

![Untitled](/assets/images/htbsherlock/safecracker/encrypted.png)

**Answer**: 33

### What is the name of the process that the unpacked executable runs as?

We can proceed to extract the suspicious binary and load it into IDA. Looking at main, we see a call to `_execl` at `0x3A7BE`. One of the arguments passed to this function is the string `PROGRAM` which is likely the process name.

![Untitled](/assets/images/htbsherlock/safecracker/execl.png)

**Answer**: PROGRAM

### What is the XOR key used for the encrypted strings?

I was only able to answer this question after performing some reverse engineering to understand how the malware unpacks itself. If we load the binary into Detect it Easy (DiE), we can see that there is a section that has relatively high entropy. This may indicate encrypted strings or packed binary.  

![Untitled](/assets/images/htbsherlock/safecracker/entropy.png)

After answering some of the next few questions, we understood that the malware decrypts bytes found in the `.data` section then decompresses it using zlib. Thus, we can use the following code to extract, decrypt and decompress to unpack the next stage payload. 

```python
import zlib
from Crypto.Cipher import AES
from binascii import unhexlify

def main():
    offset = 0x2883a0
    size = 0x18FB40

    with open('<filepath>', 'rb') as f:
        enc = f.read()[offset:offset+size]

    print(hex(len(enc)))
    key = unhexlify('a5f41376d435dc6c61ef9ddf2c4a9543c7d68ec746e690fe391bf1604362742f')
    iv = unhexlify('95e61ead02c32dab646478048203fd0b')

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(enc)
    unpacked = zlib.decompress(decrypted)

    with open('<filepath>', 'wb') as f:
        f.write(unpacked)

if __name__=='__main__':
    main()
```

Note that the offset used is `0x2883a0` instead of `0x2893A0` as seen in IDA because the raw offset on disk is `0x2883a0`. Additionally, we also need to change the size to `0x18FB40` to ensure that it is divisible by 16.

![Untitled](/assets/images/htbsherlock/safecracker/encbytes.png)

After loading the new binary into IDA, we can see reference to a string `daV324982S3bh2` which is likely the xor key. 

![Untitled](/assets/images/htbsherlock/safecracker/xorkey.png)

**Answer**: daV324982S3bh2

### What encryption was the packer using?

The malware likely uses OpenSSL API to perform encryption. We can confirm this finding by looking at the call to `0x3FC70`. 

![Untitled](/assets/images/htbsherlock/safecracker/evpdecryptinit.png)

If we inspect the function `0x3FC70`, we eventually find string referecing `crypto/evp/evp_enc.c`. Googling for this string brings us to the source code of the file. Hence, this function may be related to OpenSSL `evp_enc.c`. 

![Untitled](/assets/images/htbsherlock/safecracker/evpenc.png)
![Untitled](/assets/images/htbsherlock/safecracker/opensslgoogle.png)

We can look at OpenSSL wiki page [1] to see how we can use the functions to perform encryption and decryption. This will allow us to identify functions related to OpenSSL.

If we look at the call to `0x3E2E0`, the return value of this function is later the second parameter for `EVP_DecryptInit_ex`. This corresponds to the function definition of `EVP_DecryptInit_ex`, which we know that this function returns the `EVP_CIPHER` structure.

![Untitled](/assets/images/htbsherlock/safecracker/evpdecryptinit.png)

We can add this structure into IDA, which reveals the `do_cipher` and `init` functions. 

![Untitled](/assets/images/htbsherlock/safecracker/evpcipherst.png)

We are interested in the first field which corresponds to the `nid` value of `0x1AB`. We can cross reference `nid.h` [2] which lists the corresponding nid value for each algorithm. The nid value of `0x1AB` corresponds to AES-256-CBC.

![Untitled](/assets/images/htbsherlock/safecracker/aescbc.png)

**Answer**: AES-256-CBC

### What was the encryption key and IV for the packer?

Since we can identify all the OpenSSL related functions, we can focus on the call to `EVP_DecryptInit_ex` at `0x3A337`. The key and IV are passed into this function as parameters.

![Untitled](/assets/images/htbsherlock/safecracker/evpdecryptinit.png)

If we look at the previous function block, we can see calls to `0x3A95D` and the key and IV are the second parameter to this function. Besides that, two hard coded values (`a5f41376d435dc6c61ef9ddf2c4a9543c7d68ec746e690fe391bf1604362742f` and `95e61ead02c32dab646478048203fd0b`) is the first argument to this function. `0x3A95D` is likely the hex decoding function, and the output of this function will be the key and IV. 

![Untitled](/assets/images/htbsherlock/safecracker/unhexlify.png)

**Answer**: a5f41376d435dc6c61ef9ddf2c4a9543c7d68ec746e690fe391bf1604362742f:95e61ead02c32dab646478048203fd0b

### What was the name of the memoryfd the packer used?

If we look at `0x3A5B0`, we see the string `test` which is passed to the function `memfd_create`. This function creates an anonymous file and returns a file descriptor that refers to it. 

![Untitled](/assets/images/htbsherlock/safecracker/memfd.png)

**Answer**: test

### What was the target directory for the ransomware?

We can look at the unpacked malware in IDA and we should see a reference to `/mnt/c/Users` at `0x4A266`. This is likely the targeted directory.

![Untitled](/assets/images/htbsherlock/safecracker/targeteddir.png)

Additionally, if we look at the MFT, we can also see that the encrypted files are found in `C:\Users` which corroborate with the findings.

![Untitled](/assets/images/htbsherlock/safecracker/targeteddirfiles.png)

**Answer**: /mnt/c/Users

### What compression library was used to compress the packed binary?

We can see that after performing a decryption routine, the program calls the function `0x3A3CB`. Within this function is the string `1.2.13`. This is likely a reference to the version number of the compression library.

![Untitled](/assets/images/htbsherlock/safecracker/version.png)

After the call to `0x3A3CB`, we then see a call to `0x3A4AC` which is likely to print the error for `0x3A3CB`.

![Untitled](/assets/images/htbsherlock/safecracker/printerror.png)

Within this function are references to strings such as `ZDATA` and `ZMEM`.

![Untitled](/assets/images/htbsherlock/safecracker/references.png)

Searching for these strings leads us to the compression library used, zlib.

![Untitled](/assets/images/htbsherlock/safecracker/zlib.png)

**Answer**: zlib

### The binary appears to check for a debugger, what file does it check to achieve this?

The function `0x4AD2C` is responsible for performing checks to detect a debugger. We can see the first file it calls `fopen` on is `/proc/self/status`.

![Untitled](/assets/images/htbsherlock/safecracker/antidebug.png)

**Answer**: /proc/self/status

### What exception does the binary raise?

We can see that the binary raises the signal 11. This is equivalent to `SIGSEGV`.

![Untitled](/assets/images/htbsherlock/safecracker/exception.png)

**Answer**: SIGSEGV

### Out of this list, what extension is not targeted by the malware? .pptx,.pdf,.tar.gz,.tar,.zip,.exe,.mp4,.mp3

The malware checks the file extension at `0x4AB61` if it is within the list to target. However, this list is encrypted using the xor key `daV324982S3bh2`. 

![Untitled](/assets/images/htbsherlock/safecracker/checkext.png)

Hence we can write the following python script to decrypt the file extensions.

```python
def main():
    encrypted = "4A 11 32 55 00 4A 05 39 50 4A 00 4A 11 26 47 00 4A 11 26 47 4A 00 4A 05 39 50 00 4A 1B 3F 43 00 4A 0B 26 54 00 4A 11 38 54 00 4A 06 3F 55 00 4A 0C 26 00 4A 0C 26 07 00 4A 0C 39 45 00 4A 15 37 41 1C 53 43 00 4A 15 37 41 00".split(" ")
    encrypted = [int(x, 16) for x in encrypted]

    key = "daV324982S3bh2"
    output = []
    temp = ""
    j = 0

    for i in range(len(encrypted)):
        if encrypted[i] == 0:
            output.append(temp)
            temp = ""
            j = 0
        else:
            temp += chr(encrypted[i] ^ ord(key[j % len(key)]))
            j += 1

    print(output)

if __name__=='__main__':
    main()
```

This gives us the following file extensions.

```
['.pdf', '.docx', '.ppt', '.pptx', '.doc', '.zip', '.jpg', '.png', '.gif', '.mp', '.mp4', '.mov', '.tar.gz', '.tar']
```

**Answer**: .exe

### What compiler was used to create the malware?

We can load the malware into DiE which will show us the compiler used.

![Untitled](/assets/images/htbsherlock/safecracker/compiler.png)

**Answer**: gcc

### If the malware detects a debugger, what string is printed to the screen?

If we look at the function `0x4ADD8`, we can see a string `*******DEBUGGED********`. We can look into `0x4AD2C` which is called before the string was printed.

![Untitled](/assets/images/htbsherlock/safecracker/debugged.png)

In this function `0x4AD2C`, we see that the malware reads the file `/proc/self/status` and attempts to find the string `TracerPid`. 

![Untitled](/assets/images/htbsherlock/safecracker/debugger.png)

If it manages to find `TracerPid`, it then returns the value for the `TracerPid` field. If this value is not zero, then the process is being debugged.  

![Untitled](/assets/images/htbsherlock/safecracker/tracerpid.png)

**Answer**: \*\*\*\*\*\*\*DEBUGGED\*\*\*\*\*\*\*\*

### What is the contents of the .comment section?

We can look at the sections in the malware using DiE. The `.comment` section contains the string `GCC: (Debian 10.2.1-6) 10.2.1 20210110`.

![Untitled](/assets/images/htbsherlock/safecracker/debian.png)

**Answer**: GCC: (Debian 10.2.1-6) 10.2.1 20210110

### What file extension does the ransomware rename files to?

The ransomware renames files to the `*.31337` extension. We can find this information by looking at the MFT.

![Untitled](/assets/images/htbsherlock/safecracker/encrypted.png)

**Answer**: .31337

### What is the bitcoin address in the ransomware note?

We can open the ransomware note and get the bitcoin address.

![Untitled](/assets/images/htbsherlock/safecracker/ransomnote.png)

**Answer**: 16ftSEQ4ctQFDtVZiUBusQUjRrGhM3JYwe

### What string does the binary look for when looking for a debugger?

Based on an earlier question, we will know that the binary looks for the string `Tracerpid` when looking for a debugger.

![Untitled](/assets/images/htbsherlock/safecracker/debugger.png)

**Answer**: Tracerpid

### It appears that the attacker has bought the malware strain from another hacker, what is their handle?

We can look at the strings output of the malware and we should find a reference to a path. The username is likely the handle of the hacker.

![Untitled](/assets/images/htbsherlock/safecracker/user.png)

**Answer**: blitztide

### What system call is utilised by the binary to list the files within the targeted directories?

The malware calls `_readdir` to list files within a directory. If we look at the manual page for `_readdir` [4] we can find references to `getdents` [5] which is likely the actual system call used to list files within a directory.

![Untitled](/assets/images/htbsherlock/safecracker/readdir.png)

**Answer**: readdir

### Which system call is used to delete the original files?

The malware calls `_remove` at `0x4A781` to delete the original file. We can see the man page for `_remove` [6] which says that unlink is used to delete files.

![Untitled](/assets/images/htbsherlock/safecracker/remove.png)

**Answer**: unlink

## References

[1] OpenSSL. (n.d.). *EVP Symmetric Encryption and Decryption.* [Online]. Available at: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption. (accessed on 31 Aug 2025)

[2] *evp_cipher_st Struct Reference.* [Online]. Available at: https://docs.huihoo.com/doxygen/openssl/1.0.1c/structevp__cipher__st.html. (accessed on 31 Aug 2025)

[3] *nid.h.* [Online]. Available at: https://boringssl.googlesource.com/boringssl/+/HEAD/include/openssl/nid.h. (accessed on 31 Aug 2025)

[4] *readdir(2) — Linux manual page.* [Online]. Available at: https://man7.org/linux/man-pages/man2/readdir.2.html. (accessed on 31 Aug 2025)

[5] *getdents(2) — Linux manual page.* [Online]. Available at: https://man7.org/linux/man-pages/man2/getdents.2.html. (accessed on 31 Aug 2025)

[6] *remove(3) — Linux manual page.* [Online]. Available at: https://man7.org/linux/man-pages/man3/remove.3.html. (accessed on 31 Aug 2025)