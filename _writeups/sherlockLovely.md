---
title: 'HTB - Sherlock (Lovely Malware)'
layout: single
author_profile: true
permalink: /writeups/sherlockLovely
excerpt: 'Writeup for HackTheBox Lovely Malware (Sherlock)'
toc: true
toc_sticky: true
toc_label: Questions
---
## About
A writeup for a HackTheBox [**Lovely Malware (Sherlock)**](https://app.hackthebox.com/sherlocks/Lovely%20Malware) completed on <date>.

![Untitled](/assets/images/htbsherlock/lovely/completed.png)

## Scenario

An employee at NeirCyber Security discovered a suspicious file named employee_benefits.exe on their desktop. The employee found the file after returning from lunch and immediately reported it to the IT security team, suspecting that it could be malicious. The objective is to reverse engineer the file and dissect its inner workings. This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.

A single zip file (lovelymalware.zip, MD5: <md5>>) was given.

The diffculty of this sherlocks is because the malware dynamically resolves all API functions used. Thus if one looks at the import section they will view very little imports. This sherlock can be solved dynamically, or manually by trying to resolve the functions used. 

To solve this sherlock through static analysis, we have to understand the API hashing algorithm which can be found at 0x140003CE0. Appendix B shows the python implementation of this API hashing. 

![Untitled](/assets/images/htbsherlock/lovely/apihashing.png)

Thus since we understand the API hashing algorithm, we can write a script which calculates all hashes in common DLL like kernelbase.dll, kernel32.dll, ntdll.dll, and advapi.dll. The python implementation can be found in Appendix A.

## Task

### What is the SHA256 hash of the malware?

We can use MalCat to get the SHA256 hash of the malware.

![Untitled](/assets/images/htbsherlock/lovely/sha256.png)

**Answer**: 

### The malware uses a global mutex to ensure that only one instance of it is being executed at the same time. What is the name of the mutex?

The Windows API CreateMutexA is usually used to create a global mutex. Malware usually creates a global mutex as an infection marker so that the compromised machine is only infected once. 

Hence we can set a breakpoint in x64 dbg using the command `setbpx CreateMutexA` and see the arguments passed into the Windows API. The mutex name is On3_S1d3d_hard.

![Untitled](/assets/images/htbsherlock/lovely/mutex.png)

```C
HANDLE CreateMutexA(
  [in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,
  [in]           BOOL                  bInitialOwner,
  [in, optional] LPCSTR                lpName
);
```

The malware dynamically resolves CreateMutexA using the function at 0x140004840 and the hash of CreateMutexA is 0x9774399D.

![Untitled](/assets/images/htbsherlock/lovely/dmutex.png)

Before calling CreateMutexA, the malware decrypts a hex string using the password `Love_Her`. The decryption routine is shown in Appendix A. 

![Untitled](/assets/images/htbsherlock/lovely/dmutex1.png)

**Answer**: Global\On3_S1d3d_hard

### The malware uses a decryption routine to decrypt its important strings. What is the decryption key used for that?

The decryption routine can be found at the function 0x140003550. Its a simple repeating key xor algorithm, but each ciphertext is subtracted with its position first before the xor operation.

![Untitled](/assets/images/htbsherlock/lovely/dec.png)

**Answer**: Love_Her

### The malware checks the parent process to see if it started normally or under a debugger. What is the expected name for the parent process?

The function at 0x140007EA0 is responsible for checking if the program started normally or under a debugger. The process first retrieve it's process id. Next, it iterates through all process by using Windows API `CreateToolHelp32Snapshot`, `Process32FirstW` and `Process32NextW`. If the process id matches the current process, the loop breaks.

![Untitled](/assets/images/htbsherlock/lovely/prociter.png)

It then enters this function block which calls `OpenProcess` and `GetModuleFileNameExA` to get the full module path of the parent process. It then construct the path to explorer.exe. The malware finally compares the module path of the parent process and the path to explorer.exe. 

![Untitled](/assets/images/htbsherlock/lovely/checkparent.png)

We can confirm this theory by looking at the debugger. `[rsp+28]` contains the full path to explorer.exe while `[rsp+290]` contains the parent process name. Thus, this is the function (`0x140003C60`) responsible for checking if the parent process is explorer.exe. `0x140003C60` returns 0 if the string does not match, otherwise it returns 1.

![Untitled](/assets/images/htbsherlock/lovely/strcmp.png)

Therefore, if the parent process is not as expected (C:\Windows\explorer.exe), the function 0x140007EA0 returns 0.

![Untitled](/assets/images/htbsherlock/lovely/prologue.png)

**Answer**: explorer.exe

### The malware tries to turn off the computer if it suspects it is running a debugger. What is the Windows API used for that?

We know that the function `0x140007EA0` checks if the parent process is as expected. `0x140007EA0` is called by `0x140008010` and the comparison result is used by 0x140007E20 (CallExitWindowsExWrapper). 

![Untitled](/assets/images/htbsherlock/lovely/exit.png)

0x140007E20 first calls `CurrentProcess` to get a handle to the current running process and tries to assign itself the SeShutdownPrivilege.

![Untitled](/assets/images/htbsherlock/lovely/adjustpriv.png)
![Untitled](/assets/images/htbsherlock/lovely/seshutdown.png)

With the appropriate privilege, the process then calls ExitWindowsEx with the `uFlags` being `EWX_FORCE | EWX_SHUTDOWN`.

![Untitled](/assets/images/htbsherlock/lovely/exitwindows.png)

**Answer**: ExitWindows

### The malware targets a specific directory and its subdirectories in the drive where the Windows OS is installed. What is the name of this directory?

We see that in `sub_140008D40` there is a call to get the Windows directory. This calls the function `0x140002010` is a wrapper which calls the Windows API `GetWindowsDirectoryA` and it returns the root directory. The root directory was appended with the string `Users\*` which becomes the path to the Users directory. The string `Users\*` was originally encrypted and only decrypted at `0x140008DC9`. 

![Untitled](/assets/images/htbsherlock/lovely/usersdir.png)

The directory to Users was then pass into the function `sub_140008960` which is responsible for iterating through the directory and traversing it. This is evident from the calls to Windows API like `FindFirstFileW` and `FindNextFileW`, APIs which are used to search a directory. Hence, the malware likely targets only the Users directory.

![Untitled](/assets/images/htbsherlock/lovely/file.png)

**Answer**: Users

### Which among these file extensions does the malware not target {png, docx, exe, 7z, zip}?

We can attempt to detonate the malware and look for files that are not encrypted in the Users directory. If we look at all the files, we will notice that files with the `.exe` extensions are not encrypted. We can still run any `exe` present in the Users directory.

In most cases, ransomware does not try to encrypt files with `.exe` or `.dll` extensions and files in the `C:\\Windows\\System32`. The reason is that these files may be important for the operation of the OS and encrypting them might cause the system to crash. Encrypting `.exe` or `.dll` may lead to the ransomware encrypting itself as well.

**Answer**: .exe

### What is the encryption algorithm used for encrypting files? Algorithm-KeyLength?

The malware dynamically loads CryptAcquireContextA and CryptCreateHash at 0x14000233B and 0x140002375 respectively. When we look at the arguments to these two functions we can understand the encryption algorithm used.

```C
BOOL CryptAcquireContextA(
  [out] HCRYPTPROV *phProv,
  [in]  LPCSTR     szContainer,
  [in]  LPCSTR     szProvider,
  [in]  DWORD      dwProvType,
  [in]  DWORD      dwFlags
);

BOOL CryptCreateHash(
  [in]  HCRYPTPROV hProv,
  [in]  ALG_ID     Algid,
  [in]  HCRYPTKEY  hKey,
  [in]  DWORD      dwFlags,
  [out] HCRYPTHASH *phHash
);
```

More specifically, we are interested in the `dwProvType` and `Algid` which corresponds to PROV_RSA_AES and CALG_SHA_256.

![Untitled](/assets/images/htbsherlock/lovely/crypto.png)

**Answer**: AES-256

### Before the malware begins its encryption process, it attempts to disable all methods of recovering the original data. What is the full shell command executed for this?

We recovered an encrypted string with the following command.

```cmd
/c vssadmin.exe Delete Shadows /All /Quiet & bcdedit /set {default} recoveryenabled No & bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

This encrypted string was decrypted at the address 0x140003440 and cmd.exe was decrypted at 0x140003462.

![Untitled](/assets/images/htbsherlock/lovely/decVSC.png)

Afterwards the malware sets up the SHELLEXECUTEINFOA structure which is later pass as an argument to the function `ShellExecuteExA`. Thus we can deduce that the malware tries to use cmd.exe to run the command.

![Untitled](/assets/images/htbsherlock/lovely/delVSC.png)

**Answer**: cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet & bcdedit /set {default} recoveryenabled No & bcdedit /set {default} bootstatuspolicy ignoreallfailures

### Once the malware encrypts files, it sends info about the key used and the ID of the victim. Please provide the format used for this?

The malware make use of TlsCallback to set up the encryption key 'Love_Her'. It then performs memcpy operations on some strings in the binary. We attempted to decrypt some of them and found an encrypted string at `0x14000B7F0` that decrypts to a dictionary format.

![Untitled](/assets/images/htbsherlock/lovely/infoformat.png)
![Untitled](/assets/images/htbsherlock/lovely/decformat.png)

If we find cross references to the decrypted string, we see that it was passed as a parameter to the function at `0x140007780` which calls `vsprintf` to create a formatted string. 

![Untitled](/assets/images/htbsherlock/lovely/printfmgstring.png)

Eventually, the formatted string was passed as a parameter to `send`. Thus, this confirms that that is the format used.

![Untitled](/assets/images/htbsherlock/lovely/send.png)

**Answer**: {'Name' : %s , 'Computer' : %s , 'Proc' : %s , 'Key' : %s , 'Id' : %s}

### What is the IP and port utilized by the malware author?

We note that the IP is encrypted and decrypting it reveals that the IP address is 192.168[.]1[.]104. We can search for the usage of this IP address which leads us to the call to InetPtonW. 

![Untitled](/assets/images/htbsherlock/lovely/inetptonw.png)

If we look at the function call at `0x140007A68` we realise that it `htons` is called. This function is responsible for converting u_short from the host to TCP/IP network byte order. Thus this means that 8000 is likely the port number.

![Untitled](/assets/images/htbsherlock/lovely/port.png)

**Answer**: 192.168[.]1[.]104:8000

### What is the extension added to the encrypted files?

We can detonate the malware and view the extensions added to encrypted files.

![Untitled](/assets/images/htbsherlock/lovely/ext.png)

Otherwise by decrypting all the encrypted strings we can also recover the extension. 

**Answer**: .naso

### What is the Bitcoin address used by the malware author?

A ransomnote was dropped after the malware was detonated in the VM. This ransomnote included the Bitcoin address used by the malware author.

![Untitled](/assets/images/htbsherlock/lovely/ext.png)

**Answer**: bc1qntgwduujdjnfv6txwxugdsx6nw5mfhgqa4nn82

### Can you decrypt the file provided as an attachment and provide its SHA256 hash?

We know that the ransomware uses AES-256 as the encryption algorithm and that the key is transmitted to the attacker over the network. Thus, we can retrieve the key and attempt to write a python script to decrypt the attachment. 

We can set a Wireshark filter `tcp.dstport == 8000` to find the packet sent. Looking at the TCP stream, we can find the key.

![Untitled](/assets/images/htbsherlock/lovely/key.png)

The IV is likely embedded within the encrypted file. Thus to recover the IV we first have to understand how the malware generates and stores the IV. First we see a call to generate 16 bytes randomly after mapping a file into the process. This mapped file is the file to be encrypted.

![Untitled](/assets/images/htbsherlock/lovely/genrand.png)

The following image shows the generated bytes. 

![Untitled](/assets/images/htbsherlock/lovely/iv.png)

Next there is a call to generate some data using `sub_140001610`.

![Untitled](/assets/images/htbsherlock/lovely/gendata.png)

The following image shows the before and after calling `sub_140001610`. Note that 256 bytes was generated.

![Untitled](/assets/images/htbsherlock/lovely/beforegen.png)
![Untitled](/assets/images/htbsherlock/lovely/aftergen.png)

We then see two memcpy operations. The first memcpy copies the IV to the end of the buffer. The second memcpy copies the contents of the file after the IV. The file contents was encrypted at the call to `sub_140001EE0` (`AESEncrypt`). Thus we can conclude that the IV can be found before the encrypted file contents.

![Untitled](/assets/images/htbsherlock/lovely/encrypt.png)

The following images shows the before and after of the buffer when the memcpy operations are performed. The last image shows the encrypted file. 

![Untitled](/assets/images/htbsherlock/lovely/memcpy_1.png)
![Untitled](/assets/images/htbsherlock/lovely/memcpy_2.png)
![Untitled](/assets/images/htbsherlock/lovely/encrypted.png)

Finally the malware unmaps the file from the process, writing the encrypted contents to disk. We can see the IV at the start of the file.

![Untitled](/assets/images/htbsherlock/lovely/unmapview.png)
![Untitled](/assets/images/htbsherlock/lovely/flushing.png)

Thus we now have the knowledge to create the decryption script.

```python

```

**Answer**: 