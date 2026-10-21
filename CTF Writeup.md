**TEAM NAME :TP**

**TEAM MEMBERS:MADHINA.M,JAILAKSHMI E**

**1.CHALLANGE:WELCOME OR START FLAG**


IT was given by them to start


**THE FLAG:OWASP{c43s4r\_c1ph3r\_1s\_34sy\_t0\_cr4ck}**

**2.CHALLANGE:WEB EXPLOITATION**

we opened the website link which they gave and we go a web site with "visit/profile/1 to visit the profile".

we just added the "/profile/1" at the end of the link they gave us. we got a new website with a profile and it's role as user but we need the admin profile as given in question.

we tried to change the num after the profile. From 2-4 we got user profile and from 5-10 no user is found. at last for 0 we got the admin's profile i which we got the flag.



**3.CHALLANGE: Intercepted XOR Encrypted Data**


In the file the gave us the key length:6 bytes, Algorithm: XOR and encrypted (hex): "3c322221350f0b55112d54072c161a1f0847071752113a1742150b411709"

HINT:The key is a common English word

python code:

data = "3c322221350f0b55112d54072c161a1f0847071752113a1742150b411709"

encrypted = bytes.fromhex(data)

key = b"secret"

decrypted = bytes(

&#x20;   byte ^ key\[i % len(key)]

&#x20;   for i, byte in enumerate(encrypted)

)

print(decrypted.decode("ascii"))

in this coding:

bytes.formhex(data)-this to covert the hexadecimal string into encrypted bytes.

key = b"secret"-six byte key

i % len(key)-repeats the key from its beginning after every six bytes.

decode("ascii")-this code converts the resulting bytes into readable text


**THE FLAG:OWASP{x0r\_1s\_symm3tr1c\_c1ph3r}**


**4.CHALLANGE:WEAK ENCRYPTION** 


in the file they gave us Algorithm: Custom XOR, Key length: 4 bytes, Encrypted flag (hex):"0e160012113a3672752a1e2a72381e2c752a72321e727532381e3671332a3c" and 

Hint: The attacker used a very weak key pattern. 

python code:

data = "0e160012113a3672752a1e2a72381e2c752a72321e727532381e3671332a3c"

encrypted = bytes.fromhex(data)

key = b"AAAA"

decrypted = bytes(

&#x20;   byte ^ key\[i % len(key)]

&#x20;   for i, byte in enumerate(encrypted)

)

print(decrypted.decode("ascii"))

same as 2 flag capture but the key changes as AAAA to define the four byte key 


**THE FLAG:OWASP{w34k\_k3y\_m4k3s\_34sy\_w0rk}**


**5.CHALLANGE:MULTI-LAYER ENCODED MESSAGE**


In the file we got like we should encoding layers detected in the order:

1\. Base64

2\. ROT13

3\. Base64

4\. Reverse

Encoded data:

=0TPENXbXNjW1UUUvNXc692aERlW3VjMaNXQR9maTFVcrh0SvdzTxg0TxFzR

python code used to find flag:

import base64

import codecs

data = "=0TPENXbXNjW1UUUvNXc692aERlW3VjMaNXQR9maTFVcrh0SvdzTxg0TxFzR

step1 = data\[::-1]

print("After reversing:", step1)

step2 = base64.b64decode(step1).decode("utf-8")

print("After first Base64:", step2)

step3 = codecs.decode(step2, "rot\_13")

print("After ROT13:", step3)

flag = base64.b64decode(step3).decode("utf-8")

print("Flag:", flag)

reverse by \[::-1]

base 64 into bytes using "base64.b64decode()"

.decode("utf-8").to convert it to a string. then we will get the output as "G1qOH1O7oKHkqQSjoQAsZ25wZTDkozqsoQE5Z3WmsD=="

codecs.decode(step2, "rot\_13") this code is used to rot13 that means to shift the positions by 13 times afer that we get output as "T1dBU1B7bXUxdDFwbDNfM25jMGQxbmdfbDR5M3JzfQ=="

when we 2nd time base64 decode it we wil get the flag


**THE FLAG:OWASP{c43s4r\_c1ph3r\_1s\_34sy\_t0\_cr4ck}**


**6.CHALLANGE:**


we got Source: 192.168.1.105 


THE CODE:

hex\_data = "4F 57 41 53 50"

data = bytes.fromhex(hex\_data)

text = data.decode("ascii")

print(text)


hex\_data = "....." it Stores the hexadecimal string

bytes.fromhex()	Converts hexadecimal into bytes

.decode("ascii")Converts bytes into readable characters


**THE FLAG:OWASP{h3x\_d4mp5\_4r3\_y0ur\_fr13nd}**


**7.CHALLANGE:ENCRYPTED MESSAGE INTERCEPTED**


given was like encoding: Multiple layers detected, encoded data:

"Vm10U1IyRXhSbk5XV0doU1lXMVNZVmxYZUV0T2JGSlpZMFp3VGxKdFp6SlZiVFYzVjFVeGNWVnFUbUZTVm1zd1dsY3hTMlJHVW5WaVIzaFlVbFZzTTFaR1dsTlJNbEpZVjJ4S1VWWkVRVGs9"


python code used:

import base64

data = (

&#x20;   "Vm10U1IyRXhSbk5XV0doU1lXMVNZVmxYZUV0T2JGSlpZMFp3"

&#x20;   "VGxKdFp6SlZiVFYzVjFVeGNWVnFUbUZTVm1zd1dsY3hTMlJH"

&#x20;   "VW5WaVIzaFlVbFZzTTFaR1dsTlJNbEpZVjJ4S1VWWkVRVGs9"

)


layer = 1


while True:

&#x20;   try:

&#x20;       decoded = base64.b64decode(data, validate=True)

&#x20;       text = decoded.decode("utf-8")

&#x20;       print(f"Layer {layer}: {text}")

&#x20;       data = text

&#x20;       layer += 1

&#x20;   except (ValueError, UnicodeDecodeError):

&#x20;       print("\\nFinal decoded message:", data)

&#x20;       break


Layer 1: VmtSR2ExRnNWWGhSYW1SYVlXeEtObFJZY0ZwTlJtZzJVbTV3V1UxcVVqTmFSVmswWlcxS2RGUnViR3hYUlVsM1ZGWlNRMlJYV2xKUVZEQTk=

Layer 2: VkRGa1FsVXhRamRaYWxKNlRYcFpNRmg2Um5wWU1qUjNaRVk0ZW1KdFRubGxXRUl3VFZSQ2RXWlJQVDA9

Layer 3: VDFkQlUxQjdZalJ6TXpZMFh6RnpYMjR3ZEY4emJtTnllWEIwTVRCdWZRPT0=

Layer 4: T1dBU1B7YjRzMzY0XzFzX24wdF8zbmNyeXB0MTBufQ==

Layer 5: OWASP{b4s364\_1s\_n0t\_3ncrypt10n}


**THE FLAG:OWASP{b4s364\_1s\_n0t\_3ncrypt10n}**


**8.CHALLANGE:Intercepted Message**


When we opened the file we got:

Date: 44 BC

Source: Roman Empire

Cipher: Caesar

Encrypted message:

BJNFC{p43f4e\_p1cu3e\_1f\_34fl\_g0\_pe4px}

now we need to decrypt the encrypted message, so we used ROT13.

Python code:

import codecs

encrypted = "BJNFC{p43f4e\_p1cu3e\_1f\_34fl\_g0\_pe4px}"

flag = codecs.decode(encrypted, "rot\_13")

print("Decrypted flag:", flag)


**THE FLAG:OWASP{c43s4r\_c1ph3r\_1s\_34sy\_t0\_cr4ck}**

**THE END**

