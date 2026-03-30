# Visual Approach - CTF Writeup

## Challenge Overview

| Field | Value |
|-------|-------|
| **Challenge Name** | Visual Approach |
| **Category** | Cryptography |
| **Difficulty** | Medium |
| **Flag** | `FYPCTF26{xor_stream_reuse_breaks_visual_crypto}` |

---

## Challenge Description

A startup built an image-sharing product around 2-out-of-2 visual cryptography. They split a secret monochrome image into two shares, added a custom "obfuscation" pass, then encrypted each share with a stream cipher. You are given `generate.py`, two encrypted shares (`visual_share_a.enc`, `visual_share_b.enc`). Try to recover the flag without the key!

---

## Initial Analysis

### Files Provided

1. **generate.py** - The encryption/generation script
2. **visual_share_a.enc** - Encrypted share A (376 bytes)
3. **visual_share_b.enc** - Encrypted share B (376 bytes)

### Understanding the Crypto Scheme

Examining `generate.py`, the encryption process follows this pipeline:

```
FLAG → flag_to_bits() → transform_secret() → visual_share_pair() → stream_encrypt()
```

Let's break down each step:

#### 1. Flag to Bits Conversion
```python
def flag_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits
```
The flag is converted to a bit array, extracting bits from MSB to LSB for each byte.

#### 2. Transform Secret (Obfuscation Layer)
```python
def transform_secret(secret_bits: list[int]) -> list[int]:
    perm = build_permutation(len(secret_bits))
    permuted = apply_permutation(secret_bits, perm)
    return apply_running_xor(permuted)
```

Two operations are applied:
- **Permutation**: Bits are shuffled using a fixed seed (`PERMUTATION_SEED = 0x51A2B33F`)
- **Running XOR**: A cumulative XOR is applied: `out[i] = permuted[i] XOR out[i-1]` with `out[-1] = 0`

#### 3. Visual Cryptography (2-out-of-2 Scheme)
```python
def visual_share_pair(secret_bits: list[int], rng: Random) -> tuple[bytes, bytes]:
    share_a = bytearray()
    share_b = bytearray()

    for bit in secret_bits:
        a = rng.getrandbits(1)  # Random bit
        if bit == 0:
            b = a               # Shares are identical
        else:
            b = a ^ 1           # Shares differ
        share_a.append(a)
        share_b.append(b)

    return bytes(share_a), bytes(share_b)
```

This is a classic 2-out-of-2 visual secret sharing scheme:
- For secret bit = 0: Both shares get the same random bit
- For secret bit = 1: Share B gets the complement of share A's random bit

**Key property**: `share_a XOR share_b = secret_bits`

#### 4. Stream Encryption
```python
def stream_encrypt(data_a: bytes, data_b: bytes) -> tuple[bytes, bytes]:
    seed_material = f"{SEED}:{KEYSTREAM_NONCE}".encode()
    keystream = hashlib.shake_256(seed_material).digest(len(data_a))

    enc_a = bytes(x ^ k for x, k in zip(data_a, keystream))
    enc_b = bytes(x ^ k for x, k in zip(data_b, keystream))
    return enc_a, enc_b
```

Both shares are encrypted with the **same keystream** generated from SHAKE-256.

---

## The Vulnerability: Stream Cipher Key Reuse

### The Critical Flaw

Both encrypted shares use the **identical keystream**:

```python
enc_a = share_a XOR keystream
enc_b = share_b XOR keystream
```

When we XOR the two ciphertexts together:

```
enc_a XOR enc_b = (share_a XOR keystream) XOR (share_b XOR keystream)
                = share_a XOR share_b XOR keystream XOR keystream
                = share_a XOR share_b
                = secret_bits
```

The keystream cancels out completely! This is the classic **two-time pad** vulnerability.

### Why This Works with Visual Crypto

In visual cryptography:
- `share_a[i] XOR share_b[i] = secret_bit[i]`

Therefore:
- `enc_a XOR enc_b = transformed_bits` (the obfuscated secret before visual sharing)

---

## Exploitation Methodology

### Step 1: Cancel the Keystream

XOR the two encrypted shares to eliminate the keystream and recover the transformed bits:

```python
secret_xor = bytes(x ^ y for x, y in zip(enc_a, enc_b))
```

### Step 2: Extract Bits

Each byte in `secret_xor` contains a single bit of information (0 or 1). Extract the LSB:

```python
transformed_bits = [byte & 1 for byte in secret_xor]
```

### Step 3: Invert Running XOR

The running XOR transformation:
```
out[0] = permuted[0]
out[i] = permuted[i] XOR out[i-1]
```

To invert:
```
permuted[0] = out[0]
permuted[i] = out[i] XOR out[i-1]
```

### Step 4: Invert Permutation

Build the same permutation with the known seed, then compute its inverse to unshuffle the bits.

### Step 5: Convert Bits to Bytes

Group bits into bytes (8 bits each, MSB first) to recover the flag.

---

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
Visual Approach - CTF Solver
Exploits stream cipher key reuse to break visual cryptography
"""

import hashlib
from random import Random

# Constants from generate.py
SEED = 0xC0FFEE26
KEYSTREAM_NONCE = "7f6a6b657973747265616d"
PERMUTATION_SEED = 0x51A2B33F


def bits_to_bytes(bits):
    """Convert bit list to bytes (MSB first)."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def invert_running_xor(out_bits):
    """
    Invert running XOR transformation.
    running_xor: out[0] = in[0], out[i] = in[i] XOR out[i-1]
    inverse: in[0] = out[0], in[i] = out[i] XOR out[i-1]
    """
    permuted = []
    prev = 0
    for out_bit in out_bits:
        permuted_bit = out_bit ^ prev
        permuted.append(permuted_bit)
        prev = out_bit  # State for next iteration
    return permuted


def build_permutation(length):
    """Build the same permutation used in encryption."""
    perm = list(range(length))
    Random(PERMUTATION_SEED).shuffle(perm)
    return perm


def solve(enc_a, enc_b):
    """Main solver function."""
    print(f"[*] Input: {len(enc_a)} bytes per share")
    
    # Step 1: Exploit key reuse - XOR encrypted shares
    # enc_a XOR enc_b = (share_a XOR ks) XOR (share_b XOR ks)
    #                 = share_a XOR share_b
    #                 = transformed_bits (from visual crypto property)
    secret_xor = bytes(x ^ y for x, y in zip(enc_a, enc_b))
    print(f"[+] Step 1: XORed shares to cancel keystream")
    
    # Step 2: Extract bits (each byte contains one bit: 0 or 1)
    transformed_bits = [byte & 1 for byte in secret_xor]
    print(f"[+] Step 2: Extracted {len(transformed_bits)} bits")
    
    # Step 3: Invert running XOR
    permuted_bits = invert_running_xor(transformed_bits)
    print(f"[+] Step 3: Inverted running XOR")
    
    # Step 4: Invert permutation
    perm = build_permutation(len(permuted_bits))
    
    # Compute inverse permutation: inv_perm[perm[i]] = i
    inv_perm = [0] * len(perm)
    for i, j in enumerate(perm):
        inv_perm[j] = i
    
    # Apply inverse: original[i] = permuted[inv_perm[i]]
    original_bits = [permuted_bits[inv_perm[i]] for i in range(len(permuted_bits))]
    print(f"[+] Step 4: Inverted permutation")
    
    # Step 5: Convert bits back to bytes
    flag = bits_to_bytes(original_bits)
    
    return flag


def main():
    # Read encrypted shares
    with open('visual_share_a.enc', 'rb') as f:
        enc_a = f.read()
    with open('visual_share_b.enc', 'rb') as f:
        enc_b = f.read()
    
    # Solve
    flag = solve(enc_a, enc_b)
    
    print(f"\n[+] FLAG: {flag.decode()}")


if __name__ == "__main__":
    main()
```

### Execution Output

```
[*] Input: 376 bytes per share
[+] Step 1: XORed shares to cancel keystream
[+] Step 2: Extracted 376 bits
[+] Step 3: Inverted running XOR
[+] Step 4: Inverted permutation

[+] FLAG: FYPCTF26{xor_stream_reuse_breaks_visual_crypto}
```

---

## Lessons Learned

### Cryptographic Takeaways

1. **Never reuse keystreams**: The fundamental vulnerability was using the same keystream to encrypt two different messages. This completely defeats the security of a stream cipher.

2. **Visual cryptography is information-theoretically secure**: The visual sharing scheme itself is secure—without both shares, you learn nothing about the secret. However, the outer encryption layer must also be secure.

3. **Layered encryption requires careful analysis**: Each layer (obfuscation, visual crypto, stream cipher) needs to be analyzed both independently and as a whole system.

### Defense Recommendations

To fix this challenge's encryption scheme:

1. **Use unique nonces/IVs**: Each share should use a different nonce for keystream generation:
   ```python
   keystream_a = hashlib.shake_256(f"{SEED}:{nonce_a}".encode()).digest(len(data_a))
   keystream_b = hashlib.shake_256(f"{SEED}:{nonce_b}".encode()).digest(len(data_b))
   ```

2. **Use authenticated encryption**: Consider using authenticated encryption modes to detect tampering.

3. **Proper key derivation**: Use a proper KDF (like HKDF) to derive separate keys for each share from a master key.

---

## Conclusion

This challenge demonstrated how even mathematically secure primitives (visual cryptography) can be completely undermined by improper usage of symmetric encryption. The key insight was recognizing that:

1. XORing the two ciphertexts cancels the keystream
2. Visual cryptography has the property that `share_a XOR share_b = secret`
3. The obfuscation layers (permutation + running XOR) can be inverted since all parameters are known

The flag was: **`FYPCTF26{xor_stream_reuse_breaks_visual_crypto}`**

---

## Appendix: Mathematical Verification

For the curious, here's the mathematical proof of why the attack works:

Let:
- $S$ = secret bits (the flag)
- $P$ = permutation function
- $R$ = running XOR function
- $V$ = visual sharing function (produces $A, B$ where $A \oplus B = R(P(S))$)
- $K$ = keystream
- $C_A, C_B$ = encrypted shares

**Encryption:**
$$C_A = A \oplus K$$
$$C_B = B \oplus K$$

**Attack:**
$$C_A \oplus C_B = (A \oplus K) \oplus (B \oplus K) = A \oplus B = R(P(S))$$

**Recovery:**
$$S = P^{-1}(R^{-1}(C_A \oplus C_B))$$

Since we know $P$ (from `PERMUTATION_SEED`) and can compute $R^{-1}$, full recovery is possible.
