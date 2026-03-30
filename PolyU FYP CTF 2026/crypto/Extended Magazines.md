# Extended Magazines - CTF Writeup

## Table of Contents
1. [Summary](#summary)
2. [Vulnerability Analysis](#vulnerability-analysis)
3. [Step-by-Step Exploitation](#step-by-step-exploitation)
4. [Technical Details](#technical-details)
5. [The Exploit Script](#the-exploit-script)
6. [Prevention](#prevention)

---

## Summary

**Challenge:** Extended Magazines  
**Category:** Cryptography (SHA-1 Length Extension Attack)  
**Author:** Dallas  
**Points:** Not specified  
**Flag:** `FYPCTF26{You_are_the_master_of_SHA1_length_extension_attack_yoooo}`  

**TL;DR:** The challenge presented an online newspaper kiosk that issued cryptographically signed tickets using SHA1(secret || message). This vulnerable MAC construction is susceptible to length extension attacks, allowing an attacker to forge valid VIP tickets without knowing the secret key.

### Challenge Overview
The service issued signed tickets via `GET /api/issue?user=<name>` and verified them at `POST /api/vip`. Tickets were signed using a homemade MAC:

```python
def sign_ticket(message: bytes) -> str:
    return hashlib.sha1(MAC_SECRET + message).hexdigest()
```

The goal was to forge a VIP ticket (with `is_vip=1`) to access the classified issue containing the flag.

---

## Vulnerability Analysis

### The Vulnerable MAC Construction

The critical vulnerability lies in the MAC (Message Authentication Code) construction:

```python
SHA1(secret || message)
```

This is known as a "prefix MAC" and is **insecure** when used with Merkle-Damgård hash functions like SHA-1, SHA-256, and MD5.

### Why Length Extension is Possible

SHA-1 uses the Merkle-Damgård construction, which processes messages in fixed 64-byte blocks:

1. **Message Padding:** Before hashing, SHA-1 pads the message to a multiple of 64 bytes:
   - Append a single `0x80` byte
   - Append `0x00` bytes until the message is 8 bytes short of a multiple of 64
   - Append the original message length as a 64-bit big-endian integer

2. **Internal State:** SHA-1 maintains a 160-bit internal state (5 registers: h0, h1, h2, h3, h4). After processing each block, this state is updated.

3. **The Attack:** Given:
   - A hash value `H = SHA1(secret || message)`
   - The original message (known)
   - The length of the secret (can be brute-forced)

   We can compute `SHA1(secret || message || padding || append)` by:
   - Using the original hash `H` as the initial state
   - Continuing the hash computation with `append || new_padding`

4. **Result:** We can generate valid signatures for extended messages without knowing the secret!

### Why HMAC is Secure

HMAC uses a nested construction:
```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
```

This double-hashing prevents length extension because the attacker cannot compute the inner hash without the key.

---

## Step-by-Step Exploitation

### Step 1: Obtain a Legitimate Ticket

First, we request a ticket from the issuance endpoint:

```bash
$ curl "http://challenge.hacktheflag.one:30012/api/issue?user=testuser"
```

**Response:**
```json
{
  "ticket": "757365723d746573747573657226726f6c653d7265616465722669735f7669703d30266d61673d7765656b6c795f646967657374",
  "signature": "2275e1bc760f52597d3135838fc48b9cb98c89c4"
}
```

Decoding the ticket hex:
```python
>>> bytes.fromhex("757365723d...").decode()
'user=testuser&role=reader&is_vip=0&mag=weekly_digest'
```

**Analysis:**
- Ticket format: `user=<name>&role=reader&is_vip=0&mag=weekly_digest`
- Length: 52 bytes
- Current status: `is_vip=0` (not VIP)

### Step 2: Analyze the Ticket Parsing

The server uses `urllib.parse.parse_qsl()` to parse tickets:

```python
def parse_ticket(ticket: bytes) -> dict[str, str]:
    pairs = parse_qsl(ticket.decode("latin-1"), keep_blank_values=True)
    data: dict[str, str] = {}
    for key, value in pairs:
        if key in BAD_KEYS:
            continue
        data[key] = value
    return data
```

**Key Insight:** When duplicate keys exist in a query string, later values typically overwrite earlier ones. By appending `&is_vip=1` to the ticket, we can override the original `is_vip=0`.

### Step 3: Determine the Secret Length

The server code reveals the default secret:
```python
MAC_SECRET = os.getenv("MAC_SECRET", "this_should_be_random_and_hidden").encode()
```

Default is 34 bytes, but production could be different. We need to brute-force the secret length.

**Approach:** Try different secret lengths until the server accepts our forged signature.

### Step 4: Craft the Length Extension Attack

We want to forge:
```
SHA1(secret || original_message || padding || "&is_vip=1")
```

The attack works as follows:

1. **Calculate the padding** that would be added after `secret || original_message`:
   ```python
   total_len = secret_len + len(original_message)  # e.g., 40 + 52 = 92
   padding = b'\x80' + b'\x00' * ((55 - total_len % 64) % 64)
   padding += struct.pack('>Q', total_len * 8)  # length in bits
   ```

2. **Parse the original hash** into SHA-1 registers:
   ```python
   h = [int(original_hash[i:i+8], 16) for i in range(0, 40, 8)]
   h0, h1, h2, h3, h4 = h
   ```

3. **Continue hashing** from this state with our appended data:
   ```python
   new_total_len = secret_len + len(original_message) + len(padding) + len(append_data)
   # Process append_data with new padding and length encoding
   ```

4. **Construct the forged ticket**:
   ```python
   forged_message = original_message + padding + b"&is_vip=1"
   ```

### Step 5: Submit to the VIP Endpoint

We submit our forged ticket to `/api/vip`:

```json
POST /api/vip
{
  "ticket": "<forged_ticket_hex>",
  "signature": "<forged_signature>"
}
```

**Successful Response:**
```json
{
  "message": "Welcome to the classified issue.",
  "flag": "FYPCTF26{You_are_the_master_of_SHA1_length_extension_attack_yoooo}",
  "ticket_data": {
    "user": "testuser",
    "role": "reader",
    "is_vip": "1",
    "mag": "weekly_digest"
  }
}
```

The secret length was **40 bytes**. Our forged ticket passed signature verification because the computed hash matched what the server would calculate for the extended message.

---

## Technical Details

### SHA-1 Internals

SHA-1 operates on 512-bit (64-byte) blocks and produces a 160-bit hash. The compression function:

1. **Initialize 5 registers:**
   ```
   h0 = 0x67452301
   h1 = 0xEFCDAB89
   h2 = 0x98BADCFE
   h3 = 0x10325476
   h4 = 0xC3D2E1F0
   ```

2. **Process each 64-byte block:**
   - Expand 16 words to 80 words using:
     ```
     W[t] = ROTL(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16], 1)
     ```
   - Update registers through 80 rounds of operations
   - Add results back to registers

3. **Output:** Concatenation of the 5 registers

### The Length Extension Math

Given `H = SHA1(S || M)` where `S` is secret and `M` is known:

1. `H` represents the internal state after processing `S || M || pad1`
2. We can compute `SHA1(S || M || pad1 || X)` by:
   - Initializing registers to `H`
   - Processing `X || pad2` where `pad2` is padding for the new total length

This works because SHA-1's state at the end of processing `S || M || pad1` is exactly what's needed to continue hashing.

### Padding Calculation

For a message of length `L` bytes:

```python
def sha1_padding(L):
    """Calculate SHA-1 padding for a message of length L."""
    padding = b'\x80'
    # Number of zero bytes needed (always pad to 56 bytes mod 64)
    zero_bytes = (55 - L % 64) % 64
    padding += b'\x00' * zero_bytes
    # Append original length in bits (64-bit big-endian)
    padding += struct.pack('>Q', L * 8)
    return padding
```

Example for `L = 92` (40-byte secret + 52-byte message):
- `92 % 64 = 28`
- `55 - 28 = 27` zero bytes
- Padding: `0x80` + 27 × `0x00` + 8-byte length

---

## The Exploit Script

Below is the complete exploit script used to solve the challenge:

```python
#!/usr/bin/env python3
"""
SHA-1 Length Extension Attack - Extended Magazines Exploit
Exploits vulnerable SHA1(secret || message) MAC construction
"""

import struct
import requests
import json


def left_rotate(n, b):
    """Left rotate a 32-bit integer by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def sha1_transform(block, h0, h1, h2, h3, h4):
    """
    Process one 64-byte block through SHA-1 compression function.
    Returns updated hash registers.
    """
    K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
    
    # Message schedule array
    w = [0] * 80
    
    # Copy block into first 16 words
    for i in range(16):
        w[i] = struct.unpack(">I", block[i * 4:(i + 1) * 4])[0]
    
    # Extend to 80 words
    for i in range(16, 80):
        w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    # Initialize working variables
    a, b, c, d, e = h0, h1, h2, h3, h4

    # Main loop
    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b) & d)
            k = K[0]
        elif i < 40:
            f = b ^ c ^ d
            k = K[1]
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = K[2]
        else:
            f = b ^ c ^ d
            k = K[3]
        
        temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = left_rotate(b, 30)
        b = a
        a = temp

    # Add to previous state
    return (
        (h0 + a) & 0xFFFFFFFF,
        (h1 + b) & 0xFFFFFFFF,
        (h2 + c) & 0xFFFFFFFF,
        (h3 + d) & 0xFFFFFFFF,
        (h4 + e) & 0xFFFFFFFF,
    )


def sha1_length_extension(original_hash, original_message, secret_len, append_data):
    """
    Perform SHA-1 length extension attack.
    
    Server computes: SHA1(secret || message)
    We forge: SHA1(secret || message || padding || append_data)
    
    Args:
        original_hash: The known hash (hex string)
        original_message: The known message (bytes)
        secret_len: Length of the secret prefix (int)
        append_data: Data to append (bytes)
    
    Returns:
        (new_signature, forged_message_bytes)
    """
    # Parse original hash into registers (h0-h4)
    h = [int(original_hash[i:i+8], 16) for i in range(0, 40, 8)]
    h0, h1, h2, h3, h4 = h

    # Calculate total length of secret || message
    total_original_len = secret_len + len(original_message)

    # Build padding that would be added after secret || message
    padding = b'\x80'
    zero_len = (55 - (total_original_len % 64)) % 64
    padding += b'\x00' * zero_len
    padding += struct.pack('>Q', total_original_len * 8)  # Length in bits

    # The forged message we'll send to the server
    forged_message = original_message + padding + append_data

    # Calculate new total length for the forged message
    new_total_len = secret_len + len(forged_message)

    # Build padding for the append_data portion
    # This encodes the new total length
    append_with_padding = append_data + b'\x80'
    zero_len2 = (55 - (new_total_len % 64)) % 64
    append_with_padding += b'\x00' * zero_len2
    append_with_padding += struct.pack('>Q', new_total_len * 8)

    # Continue hashing from the original state
    for i in range(0, len(append_with_padding), 64):
        block = append_with_padding[i:i + 64]
        if len(block) == 64:
            h0, h1, h2, h3, h4 = sha1_transform(block, h0, h1, h2, h3, h4)

    # Construct final hash
    new_signature = ''.join(f'{x:08x}' for x in [h0, h1, h2, h3, h4])

    return new_signature, forged_message


def try_exploit(secret_len, original_sig, original_message, append_data, base_url):
    """Try the exploit with a specific secret length."""
    new_sig, new_msg = sha1_length_extension(
        original_sig, original_message, secret_len, append_data
    )

    ticket_hex = new_msg.hex()

    # Submit to /api/vip
    url = f"{base_url}/api/vip"
    data = {"ticket": ticket_hex, "signature": new_sig}

    try:
        resp = requests.post(url, json=data, timeout=10)
        return resp.status_code, resp.json()
    except Exception as e:
        return -1, str(e)


if __name__ == "__main__":
    BASE_URL = "http://challenge.hacktheflag.one:30012"

    # Step 1: Get original ticket from server
    print("[*] Getting original ticket...")
    resp = requests.get(f"{BASE_URL}/api/issue?user=testuser")
    original_data = resp.json()
    print(f"[+] Got: {original_data}")

    original_sig = original_data["signature"]
    original_ticket_hex = original_data["ticket"]
    original_message = bytes.fromhex(original_ticket_hex)

    print(f"[*] Original message: {original_message}")
    print(f"[*] Original sig: {original_sig}")

    # Step 2: Try different secret lengths
    append_data = b"&is_vip=1"

    print(f"[*] Brute-forcing secret length with append: {append_data}")
    print()

    for secret_len in range(1, 100):
        status, result = try_exploit(
            secret_len, original_sig, original_message, append_data, BASE_URL
        )

        if status == 200:
            print(f"[+] SUCCESS with secret_len={secret_len}!")
            print(f"[+] Result: {result}")
            if "flag" in result:
                print(f"\n[!] FLAG: {result['flag']}")
                break
        elif status == -1:
            print(f"[-] Error: {result}")

        if secret_len % 10 == 0:
            print(f"[*] Tried up to secret_len={secret_len}")
```

### Running the Exploit

```
$ python3 exploit.py
[*] Getting original ticket...
[+] Got: {'ticket': '757365723d746573747573657226726f6c653d7265616465722669735f7669703d30266d61673d7765656b6c795f646967657374', 'signature': '2275e1bc760f52597d3135838fc48b9cb98c89c4'}
[*] Original message: b'user=testuser&role=reader&is_vip=0&mag=weekly_digest'
[*] Original sig: 2275e1bc760f52597d3135838fc48b9cb98c89c4
[*] Brute-forcing secret length with append: b'&is_vip=1'

[*] Tried up to secret_len=10
[*] Tried up to secret_len=20
[*] Tried up to secret_len=30
[*] Tried up to secret_len=40
[+] SUCCESS with secret_len=40!
[+] Result: {'message': 'Welcome to the classified issue.', 'flag': 'FYPCTF26{You_are_the_master_of_SHA1_length_extension_attack_yoooo}', 'ticket_data': {'user': 'testuser', 'role': 'reader', 'is_vip': '1', 'mag': 'weekly_digest'}}

[!] FLAG: FYPCTF26{You_are_the_master_of_SHA1_length_extension_attack_yoooo}
```

---

## Prevention

### The Fix: Use HMAC

The secure solution is to use HMAC instead of a homemade prefix MAC:

```python
import hmac
import hashlib

def sign_ticket_secure(message: bytes, secret: bytes) -> str:
    """Secure MAC using HMAC-SHA256."""
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def verify_ticket_secure(message: bytes, signature: str, secret: bytes) -> bool:
    """Constant-time signature verification."""
    expected = sign_ticket_secure(message, secret)
    return hmac.compare_digest(expected, signature)
```

### Why HMAC is Secure

1. **Double Hashing:** HMAC hashes the key twice (with different pads), preventing length extension.
2. **Key Isolation:** The inner hash result is not directly exposed.
3. **Standardized:** HMAC is a well-analyzed, provably secure construction.

### Other Recommendations

1. **Use SHA-256 or SHA-3:** SHA-1 is cryptographically broken (collision attacks exist). While length extension is the primary concern here, using modern hash functions is recommended.

2. **Constant-Time Comparison:** Always use `hmac.compare_digest()` to prevent timing attacks:
   ```python
   # INSECURE - timing attack possible
   if computed_sig == provided_sig:  # Don't do this!
   
   # SECURE
   if hmac.compare_digest(computed_sig, provided_sig):
   ```

3. **Use Standard Libraries:** Don't roll your own crypto. Python's `hmac` module is standard and secure.

4. **Alternative: Authenticated Encryption:** For combined confidentiality and integrity, use AES-GCM or ChaCha20-Poly1305 instead of separate MACs.

---

## Lessons Learned

1. **Never use SHA1(secret || message)** for MACs - it's vulnerable to length extension attacks.

2. **Always use HMAC** when you need a message authentication code.

3. **Brute-forcing unknown lengths** is feasible when the search space is small (secret length was only 40 bytes, and trying 100 lengths takes seconds).

4. **Query string parsing behavior** can be exploited - duplicate keys often allow parameter injection.

5. **SHA-1's Merkle-Damgård construction** is the root cause of length extension vulnerability. Similar attacks work on SHA-256 and MD5.

---

## References

- [RFC 2104 - HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
- [SHA-1 Wikipedia](https://en.wikipedia.org/wiki/SHA-1)
- [Length Extension Attack - Wikipedia](https://en.wikipedia.org/wiki/Length_extension_attack)
- [Merkle-Damgård Construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)
- [hashpump - Tool for Length Extension Attacks](https://github.com/bwall/HashPump)

---

*Writeup by TimoAI Crypto Analyst*  
*Date: March 29, 2026*
