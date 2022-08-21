---
layout: single
author_profile: true
permalink: /writeups/imaginaryctf2022
excerpt: 'Writeup for Imaginary CTF 2022 on 16 July 2022 - 19 July 2022'
toc: true
toc_sticky: true
toc_label: Challenges
---

A very late writeup for Imagniary CTF 2022. The CTF was hosted from 16 July 2022 - 19 July 2022 and here are the challenges that I managed to solve.
![solved](/assets/images/imaginaryctf2022/solved.jpg)

# Pwn

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

-v tag for grep does an invert-match which allow me to find the lines which does not have "notSusFunction()".
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
