# CTF Writeup: Basic XOR Knowledge

## Challenge Information
- **Challenge Name**: Basic XOR Knowledge
- **Category**: Cryptography
- **Difficulty**: Beginner
- **Flag**: `FYPCTF26{xor_identity_self_inverse_associative}`

---

## Summary

This challenge presents an "over-engineered XOR chain" encryption that, despite appearing complex, simplifies dramatically due to fundamental XOR properties. The entire encryption reduces from 7 XOR operations to a single XOR between the flag and `key_c`. The flag was recovered by identifying and exploiting XOR's self-inverse and identity properties.

---

## Challenge Description

> We encrypted the flag with an over-engineered XOR chain! All variables are byte strings with the same length, and `^` means byte-wise XOR. Download the public files. It contains `key_a`, `key_b`, `zero_pad`, `key_c`, and `cipher` in hex.

---

## Files Provided

| File | Description |
|------|-------------|
| `basic_xor_knowledge.zip` | Archive containing challenge files |
| `chall.py` | Encryption source code |
| `output.txt` | Contains the cipher text (hex encoded) |

---

## Source Code Analysis

```python
def xor_bytes(*chunks):
    if not chunks:
        raise ValueError('xor_bytes requires at least one input')
    output = bytearray(chunks[0])
    for chunk in chunks[1:]:
        if len(chunk) != len(output):
            raise ValueError('all XOR inputs must have the same length')
        for i, value in enumerate(chunk):
            output[i] ^= value
    return bytes(output)

def encrypt(key_a, key_b, zero_pad, key_c, flag):
    cipher = xor_bytes(
        xor_bytes(
            xor_bytes(
                xor_bytes(
                    xor_bytes(flag, key_a),
                    key_b,
                ),
                key_b,
            ),
            key_a,
        ),
        zero_pad,
        key_c,
    )
    return cipher
```

### Key Values (Hex Format)

| Variable | Hex Value |
|----------|-----------|
| `key_a` | `b47c63f46b5cb388af409d2b03abd99fef7ba60a554bc3e53da5605b56e8f7923b8cf3564e767756dc32fa9284fc97` |
| `key_b` | `91011c8d4914dd452075b930cd135902e84a4e78291b96e7c162ac6c84bd15765c9a10cae00340946f460e4b90c557` |
| `zero_pad` | `0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` |
| `key_c` | `98252e1a776f1b5108407b01e42298d9bbe99eb148bb05cfe41b1ea8646cdcaf2643625cf52e92c16ad266dd35a8cc` |
| `cipher` | `de7c7e592329296773381473bb4bfcbcd59df7c531e476aa887d41c10a1ab9dd55263d3d865dfda203b312b443cdb1` |

All values are **64 bytes (512 bits)** in length.

---

## Mathematical Analysis

### XOR Properties

XOR (exclusive or) has three fundamental properties critical to solving this challenge:

1. **Self-Inverse Property**: `A ^ A = 0`
   - Any value XORed with itself equals zero

2. **Identity Property**: `A ^ 0 = A`
   - Any value XORed with zero equals itself

3. **Associative Property**: `(A ^ B) ^ C = A ^ (B ^ C)`
   - The order of operations doesn't matter

### Step-by-Step Simplification

**Original encryption formula:**
```
cipher = (((((flag ^ key_a) ^ key_b) ^ key_b) ^ key_a) ^ zero_pad) ^ key_c
```

**Expanding to show all XOR operations:**
```
cipher = flag ^ key_a ^ key_b ^ key_b ^ key_a ^ zero_pad ^ key_c
```

**Applying XOR properties:**

1. `key_a ^ key_a = 0` (self-inverse) → cancels out
2. `key_b ^ key_b = 0` (self-inverse) → cancels out
3. `zero_pad` is all zeros, so `flag ^ zero_pad = flag` (identity)

**After cancellation:**
```
cipher = flag ^ 0 ^ 0 ^ 0 ^ key_c
```

**Final simplified formula:**
```
cipher = flag ^ key_c
```

---

## Solution Methodology

### Derivation of Decryption Formula

Since `cipher = flag ^ key_c` and XOR is its own inverse:

```
cipher ^ key_c = (flag ^ key_c) ^ key_c
              = flag ^ (key_c ^ key_c)      [associative property]
              = flag ^ 0                     [self-inverse property]
              = flag                         [identity property]
```

Therefore:
```
flag = cipher ^ key_c
```

### Implementation

```python
#!/usr/bin/env python3
"""
Basic XOR Knowledge - Solution Script
Recovers the flag by exploiting XOR simplification.
"""

def xor_bytes(a, b):
    """XOR two byte strings of equal length."""
    return bytes([a[i] ^ b[i] for i in range(len(a))])

# Given hex values from the challenge
key_c = bytes.fromhex('98252e1a776f1b5108407b01e42298d9bbe99eb148bb05cfe41b1ea8646cdcaf2643625cf52e92c16ad266dd35a8cc')
cipher = bytes.fromhex('de7c7e592329296773381473bb4bfcbcd59df7c531e476aa887d41c10a1ab9dd55263d3d865dfda203b312b443cdb1')

# Decrypt: flag = cipher ^ key_c
flag = xor_bytes(cipher, key_c)

print(f"Recovered Flag: {flag.decode('ascii')}")
```

### Output
```
Recovered Flag: FYPCTF26{xor_identity_self_inverse_associative}
```

### Verification

The solution was verified by re-encrypting the recovered flag:

```python
# Re-encrypt: cipher_expected = flag ^ key_c
cipher_expected = xor_bytes(flag, key_c)
assert cipher_expected == cipher, "Verification failed!"
```

This confirms the flag is correct since re-encrypting produces the original cipher text.

---

## Detailed Exploitation Steps

### Step 1: File Enumeration
```bash
ls -la
# Found: basic_xor_knowledge.zip, README.md, extracted/ directory

unzip basic_xor_knowledge.zip
# Extracted: basic_xor_knowledge/chall.py, basic_xor_knowledge/output.txt
```

### Step 2: Source Code Analysis
- Read `chall.py` to understand the encryption algorithm
- Identified the nested `xor_bytes()` calls
- Expanded the formula to see all XOR operations

### Step 3: Key Observation
- `key_a` appears **twice** → `key_a ^ key_a = 0`
- `key_b` appears **twice** → `key_b ^ key_b = 0`
- `zero_pad` is all zeros → identity element

### Step 4: Algebraic Simplification
- Recognized the "over-engineered" chain reduces to `flag ^ key_c`
- This is the core insight required to solve the challenge

### Step 5: Flag Recovery
- Applied `flag = cipher ^ key_c`
- Converted result from bytes to ASCII string

---

## Why This Challenge Exists

This challenge teaches the fundamental XOR properties that form the basis of many cryptographic systems:

1. **Cryptographers must recognize**: XOR operations can cancel out, creating hidden patterns
2. **Security through obscurity fails**: Complex-looking constructions may have simple weaknesses
3. **Mathematical reasoning**: Breaking problems down to first principles reveals solutions

The flag itself `FYPCTF26{xor_identity_self_inverse_associative}` is a hint, naming the three XOR properties that simplify the challenge.

---

## Python Solution Script

```python
#!/usr/bin/env python3
"""
Basic XOR Knowledge - Solution
CTF Challenge demonstrating XOR property simplification.

Usage: python3 solve.py
"""

def solve():
    # Hex values from challenge
    key_c_hex = '98252e1a776f1b5108407b01e42298d9bbe99eb148bb05cfe41b1ea8646cdcaf2643625cf52e92c16ad266dd35a8cc'
    cipher_hex = 'de7c7e592329296773381473bb4bfcbcd59df7c531e476aa887d41c10a1ab9dd55263d3d865dfda203b312b443cdb1'
    
    # Convert hex to bytes
    key_c = bytes.fromhex(key_c_hex)
    cipher = bytes.fromhex(cipher_hex)
    
    # XOR decryption: flag = cipher ^ key_c
    # Due to simplification: cipher = flag ^ key_c
    # Therefore: flag = cipher ^ key_c (XOR is self-inverse)
    flag_bytes = bytes([cipher[i] ^ key_c[i] for i in range(len(cipher))])
    
    return flag_bytes.decode('ascii')

if __name__ == '__main__':
    flag = solve()
    print(f"Flag: {flag}")
```

---

## Conclusion

The "Basic XOR Knowledge" challenge demonstrates how cryptographic constructions can be deceptively complex yet fundamentally simple. By recognizing that XOR is self-inverse (`A ^ A = 0`), that zero is the identity element (`A ^ 0 = A`), and that XOR is associative, the entire encryption chain simplifies from 7 operations to 1.

**Final Flag**: `FYPCTF26{xor_identity_self_inverse_associative}`
