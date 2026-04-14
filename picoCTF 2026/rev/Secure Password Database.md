# Secure Password Database — CTF Writeup

**Challenge**: Secure Password Database  
**Category**: Reverse Engineering  
**Points**: —  
**Flag**: `picoCTF{d0nt_trust_us3rs}`

---

## 1. Challenge Description

> *I made a new password authentication program that even shows you the password you entered saved in the database! Isn't that cool?*

We are given a single binary (`system.out`) and told to connect to a remote service:

```bash
nc candy-mountain.picoctf.net 62643
```

The goal: retrieve the flag from the remote server.

Note: This is the port number of the challenge instance I used. The actual port may differ for other users, so be sure to check the challenge description on the picoCTF platform for the correct connection details.

---

## 2. Initial Reconnaissance

### File Identification

```bash
$ file system.out
system.out: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, ...
```

It's a 64-bit Linux ELF binary — not stripped (symbols are present), with PIE and stack canary protections enabled.

### Quick Strings Dump

```bash
$ strings system.out
```

Key strings that immediately stand out:

```
Please set a password for your account:
How many bytes in length is your password?
Your successfully stored password:
Enter your hash to access your account!
flag.txt
Could not open flag.txt
Failed to read the flag
obf_bytes
hash
make_secret
heartbleed.c
1 == 0
```

The strings `obf_bytes`, `hash`, `make_secret`, and `flag.txt` tell us the program:
1. Has an obfuscated byte array
2. Implements a hash function
3. Has a function to "make" a secret
4. Reads a flag file on success

### Symbol Table

```bash
$ objdump -t system.out | grep -E '(hash|make_secret|main|obf_bytes)'
```

| Address | Symbol | Size | Purpose |
|---------|--------|------|---------|
| 0x1309 | `hash` | 0x55 | Hash function |
| 0x135e | `make_secret` | 0x72 | Decodes secret + hashes it |
| 0x13d0 | `main` | 0x384 | Main program logic |
| 0x2008 | `obf_bytes` | 13 bytes | XOR-encoded secret |

---

## 3. Reverse Engineering Methodology

### Disassembly & Decompilation

With symbols present, we can jump straight to the interesting functions.

#### The `hash` Function (djb2)

Disassembling `hash` at `0x1309`:

```c
uint64_t hash(const char *s) {
    uint64_t h = 0x1505;  // 5381
    while (*s) {
        h = h * 33 + (unsigned char)*s;
        s++;
    }
    return h;
}
```

This is the classic **djb2** hash algorithm — seed value `5381` (`0x1505`), multiply by 33, add each byte. Recognizable from the constant `0x1505` and the `imul rax, 33` + `add rax, byte [rdx]` pattern in the disassembly.

#### The `make_secret` Function

At `0x135e`, `make_secret` does two things:

1. **XOR-decodes** `obf_bytes` with key `0xAA` into a buffer
2. **Calls `hash()`** on the decoded string and returns the result

#### The `main` Function

At `0x13d0`, `main` orchestrates the program:

1. Allocates a 90-byte buffer via `calloc`
2. XOR-decodes `obf_bytes` with `0xAA`, stores at `buffer+60`
3. Prompts for a password (read via `fgets`, max 50 bytes, copied with `strcpy`)
4. Prompts for password length
5. Displays the stored password as ASCII values
6. Prompts for a hash value
7. Calls `make_secret(buffer+35)` — decodes `obf_bytes` again, hashes it
8. Compares user-provided hash with the computed hash
9. If they match: opens `flag.txt` and prints the flag

### Decoding the Secret

The obfuscated bytes live at `0x2008`:

```
obf_bytes (hex): c3 ff c8 c2 92 9b 8b c0 80 c2 c4 8b 00
```

XOR each byte with `0xAA`:

```
0xC3 ^ 0xAA = 0x69 = 'i'
0xFF ^ 0xAA = 0x55 = 'U'
0xC8 ^ 0xAA = 0x62 = 'b'
0xC2 ^ 0xAA = 0x68 = 'h'
0x92 ^ 0xAA = 0x38 = '8'
0x9B ^ 0xAA = 0x31 = '1'
0x8B ^ 0xAA = 0x21 = '!'
0xC0 ^ 0xAA = 0x6A = 'j'
0x80 ^ 0xAA = 0x2A = '*'
0xC2 ^ 0xAA = 0x68 = 'h'
0xC4 ^ 0xAA = 0x6E = 'n'
0x8B ^ 0xAA = 0x21 = '!'
0x00 ^ 0xAA = 0xAA  (null terminator preserved)
```

**Decoded secret**: `iUbh81!j*hn!`

### Computing the Hash

We run the djb2 algorithm on the decoded secret:

```python
def djb2(s):
    h = 5381
    for c in s.encode():
        h = (h * 33 + c) & 0xFFFFFFFFFFFFFFFF
    return h

print(djb2("iUbh81!j*hn!"))
# Output: 15237662580160011234
```

Step-by-step trace (first few iterations):

| Step | Char | Ord | h (before) | h * 33 + ord | h (after) |
|------|------|-----|-----------|--------------|-----------|
| 0 | — | — | — | — | 5381 |
| 1 | `i` | 105 | 5381 | 177678 | 177678 |
| 2 | `U` | 85 | 177678 | 5863459 | 5863459 |
| 3 | `b` | 98 | 5863459 | 193494245 | 193494245 |
| ... | ... | ... | ... | ... | ... |
| 12 | `!` | 33 | ... | ... | **15237662580160011234** |

**Final hash**: `15237662580160011234` (hex: `0xd3770d6251b31be2`)

---

## 4. Exploitation / Solution

The program asks for three inputs:

1. **Password** — any string (stored but not validated against anything)
2. **Length** — the length of your password
3. **Hash** — compared against the internally computed djb2 hash of the secret

Since we recovered the secret and computed its hash statically, we just need to supply the correct hash value.

### Solve Script

```python
#!/usr/bin/env python3
import socket

HOST = "candy-mountain.picoctf.net"
PORT = 62643

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((HOST, PORT))

def recv_until(sock, delim=b":", timeout=5):
    data = b""
    sock.settimeout(timeout)
    try:
        while delim not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="replace")

# Read initial prompt
output = recv_until(s, b":")
print(output)

# Send any password
s.sendall(b"test\n")
output = recv_until(s, b":")
print(output)

# Send length
s.sendall(b"4\n")
output = recv_until(s, b":")
print(output)

# Send the computed hash
s.sendall(b"15237662580160011234\n")

import time
time.sleep(2)
try:
    remaining = s.recv(65536).decode(errors="replace")
    print(remaining)
except:
    pass

s.close()
```

### Manual Interaction

```bash
$ nc candy-mountain.picoctf.net 62643
Please set a password for your account: test
How many bytes in length is your password? 4
You entered: 4
Your successfully stored password:
116 101 115 116 10 0
Enter your hash to access your account! 15237662580160011234
picoCTF{d0nt_trust_us3rs}
```

---

## 5. Summary

| Step | What | How |
|------|------|-----|
| 1 | Identify binary type | `file`, `strings`, `objdump -t` |
| 2 | Locate key functions | Symbols `hash`, `make_secret`, `obf_bytes` |
| 3 | Decode the secret | XOR `obf_bytes` with `0xAA` → `iUbh81!j*hn!` |
| 4 | Identify the hash | djb2 (seed 5381, multiply by 33) |
| 5 | Compute the hash | `djb2("iUbh81!j*hn!") = 15237662580160011234` |
| 6 | Submit to service | Connect via `nc`, provide password + length + hash |
| 7 | Get flag | `picoCTF{d0nt_trust_us3rs}` |

### Key Takeaway

The binary's "security" relies on an XOR-obfuscated secret with a well-known hash algorithm. The entire validation can be defeated through static analysis — no dynamic execution or debugging required. The flag name itself (`d0nt_trust_us3rs`) is a hint that the program blindly trusts user-supplied hash input rather than deriving it server-side from a real password check.
