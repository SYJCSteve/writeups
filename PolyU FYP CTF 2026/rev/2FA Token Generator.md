# 2FA Token Generator - CTF Writeup

**Category**: Reverse Engineering  
**Challenge**: 2FA Token Generator  
**Connection**: `nc challenge.hacktheflag.one 30003`  
**Flag**: `FYPCTF26{seed_and_windows_are_all_you_need}`

---

## Executive Summary

This challenge involved reverse engineering a stripped 64-bit ELF binary that implements a custom 2FA (Two-Factor Authentication) OTP (One-Time Password) algorithm. The goal was to understand the algorithm, extract the cryptographic material embedded in the binary, implement the algorithm in Python, and use it to generate valid OTPs for the remote service.

The challenge name "seed_and_windows_are_all_you_need" is a clever play on the famous machine learning paper "Attention Is All You Need" - highlighting that understanding the embedded seed material and time windows is sufficient to solve the challenge.

---

## Table of Contents

1. [Initial Reconnaissance](#initial-reconnaissance)
2. [Static Analysis](#static-analysis)
3. [Dynamic Analysis](#dynamic-analysis)
4. [Algorithm Reverse Engineering](#algorithm-reverse-engineering)
5. [Implementation](#implementation)
6. [Verification](#verification)
7. [Service Exploitation](#service-exploitation)
8. [Conclusion](#conclusion)

---

## Initial Reconnaissance

### File Analysis

Upon downloading and extracting the challenge ZIP, we obtained a single binary:

```
$ file 2fa_token_generator
2fa_token_generator: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Key observations:
- **Architecture**: x86-64 (64-bit)
- **Type**: ELF (Executable and Linkable Format)
- **PIE**: Position Independent Executable enabled
- **Stripped**: Debug symbols removed (increases reverse engineering difficulty)

### Network Connection Test

```
$ nc challenge.hacktheflag.one 30003
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAAnEA==.QZo//nZ0rVo6qiuEoGeFxQ==
solution:
```

The service requires solving a proof-of-work (POW) challenge before accepting OTP submissions. This is a common anti-spam measure in CTF challenges.

### String Analysis

Using `strings` to extract readable text from the binary revealed important clues:

```
=== Enterprise Offline 2FA Token Generator ===
Device profile: CORP-VAULT (offline mode)
Enter the 6-digit OTP for this timestamp.
Submission timeout: %lu seconds
[ERR] Token format error. Need exactly 6 digits.
[ERR] Token expired. Please request a new code.
[OK] Token accepted. Unlocking secured archive...
FLAG: 
```

These strings confirmed the binary's purpose and the expected interaction flow.

---

## Static Analysis

### Disassembly Overview

The binary was stripped, meaning we needed to identify functions by their behavior rather than names. Using `objdump` with Intel syntax:

```bash
objdump -d -M intel 2fa_token_generator > disassembly.asm
```

We identified the key function sections by looking for:
1. Time-related system calls (`time()`)
2. Input handling (`fgets()`, `strtoul()`)
3. String comparison patterns
4. Cryptographic constants

### Cryptographic Artifacts in .rodata

Analysis of the `.rodata` (read-only data) section revealed three critical data structures:

#### 1. Permutation Table (20 bytes at 0x2250)
```
0c 0b 05 07 0e 11 03 02 08 0d 01 0a 12 00 10 04 06 09 0f 00
```

#### 2. Seed Material (20 bytes at 0x2270)
```
00 16 90 05 d2 b7 df 39 a5 c4 99 ca 18 6d 42 ba 61 01 03 00
```

#### 3. Key Material (16 bytes at 0x2290)
```
42 17 a9 5c 33 e1 7f 09 d4 6b 2e 90 1c f8 55 ab
```

### Algorithm Constants

The disassembly revealed several magic constants used in the algorithm:

```asm
mov    $0x89abcdef,%esi     ; Initial state constant
mov    $0xf1e2d3c,%r9d      ; Secondary constant
mov    $0x2468ace0,%r11d    ; Tertiary constant  
mov    $0x13579bdf,%edx     ; Quaternary constant
lea    -0x61c88647(%r8,%r10,1),%ecx  ; Golden ratio: 0x9e3779b9
```

The constant `0x9e3779b9` is notable as it's the golden ratio conjugate, commonly used in cryptographic algorithms like TEA (Tiny Encryption Algorithm).

---

## Dynamic Analysis

### GDB Debugging Strategy

Since the binary was stripped, we used GDB to trace execution and understand the flow:

```bash
gdb ./2fa_token_generator
```

Key breakpoints were set at:
1. The `time()` call to capture the timestamp
2. The OTP validation loop (identified at address 0x12b9)
3. The final comparison before success/failure

### Extracting Runtime Values

By running the binary with GDB and setting strategic breakpoints, we extracted:

1. **Time window calculation**: The binary computes `counter = (timestamp // 30) - 1`
2. **Three-window validation**: It tries three consecutive 30-second windows
3. **16-round transformation**: A complex loop performs 16 iterations of bit manipulation

### Known Test Cases

Through debugging, we captured three known input/output pairs:

| Counter | Generated OTP |
|---------|---------------|
| 59158229 | 335019 |
| 59158230 | 173188 |
| 59158231 | 36154 |

These became our reference for verifying the reversed algorithm.

---

## Algorithm Reverse Engineering

### Time Window Calculation

The binary divides the Unix timestamp by 30 to get 30-second windows:

```c
timestamp = time(NULL);
base_window = timestamp / 30;
// Tries: base_window - 1, base_window, base_window + 1
```

This is similar to TOTP (Time-based One-Time Password) algorithms used in standard 2FA systems.

### Core Algorithm Structure

The OTP generation at addresses 0x12b9-0x13ed consists of:

#### Initialization Phase
```python
# State variables initialized to constants
esi = 0x89ABCDEF
r9d = 0x0F1E2D3C
r11d = 0x2468ACE0
edx = 0x13579BDF

# Loop counters
r13d = 0x36  # Running counter for key mixing
r14d = 0     # Running counter for timestamp mixing
rbx = 0      # Loop index (0-15)
r10d = 0xFFFFFFE1  # Initial key byte source (-31)
```

#### Main Transformation Loop (16 iterations)

Each iteration performs the following operations:

1. **Load key byte**: `key_byte = KEY_MATERIAL[rbx & 0xF]`
2. **Load timestamp byte**: `ts_byte = timestamp_bytes[rbx & 7]`
3. **Mix with running counters**: XOR with r13d and r14d
4. **Update counters**: r13d += 0xB, r14d += 0x11
5. **Apply rotations**: ROL (Rotate Left) and ROR (Rotate Right) operations
6. **Update r10d**: Load next key byte for subsequent iteration

The key insight was understanding how `r10d` updates - it uses a sliding window from `KEY_MATERIAL[(iteration + 6) & 0xF]`.

#### Bit Manipulation Operations

The algorithm uses three rotation operations:
- `ROL(value, 3)` - Rotate left by 3 bits
- `ROL(value, 7)` - Rotate left by 7 bits  
- `ROL(value, 11)` - Rotate left by 11 bits
- `ROR(value, 13)` - Rotate right by 13 bits

#### Golden Ratio Constant

The magic constant `0x61c88647` (which is `-0x9e3779b9` in two's complement) appears in:

```python
temp = (r8d + r10d_temp - 0x61C88647) & 0xFFFFFFFF
```

This is a standard technique in cryptographic algorithms to provide non-linearity.

#### Final Computation

After 16 rounds:

```python
# XOR high and low 32-bits of counter
counter_high = (counter >> 32) & 0xFFFFFFFF
counter_low = counter & 0xFFFFFFFF
xor_val = counter_high ^ counter_low

# Apply final rotations
r11d_rotated = ROL(r11d, 5)
r9d_rotated = ROL(r9d, 13)
esi_rotated = ROR(esi, 5)

# Combine results
result = edx ^ xor_val ^ r11d_rotated ^ r9d_rotated ^ esi_rotated
result = result ^ ((result >> 16) & 0xFFFF)
otp = result % 1000000  # 6-digit code
```

---

## Implementation

### Python Implementation

Based on the reverse engineering analysis, we implemented the algorithm in Python:

```python
#!/usr/bin/env python3
import time

# Cryptographic material extracted from binary
KEY_MATERIAL = bytes([
    0x42, 0x17, 0xA9, 0x5C, 0x33, 0xE1, 0x7F, 0x09,
    0xD4, 0x6B, 0x2E, 0x90, 0x1C, 0xF8, 0x55, 0xAB
])

def rol32(value, shift):
    """Rotate left 32-bit value."""
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def ror32(value, shift):
    """Rotate right 32-bit value."""
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF

def generate_otp(counter):
    """
    Generate OTP for a given counter value.
    The counter should be (timestamp // 30) - 1.
    """
    timestamp_bytes = counter.to_bytes(8, 'little')
    
    # Initialize state matching the binary
    r13d, r14d, rbx = 0x36, 0, 0
    r10d = 0xFFFFFFE1
    esi = 0x89ABCDEF
    r9d = 0x0F1E2D3C
    r11d = 0x2468ACE0
    edx = 0x13579BDF
    
    # 16 rounds of transformation
    for iteration in range(16):
        key_byte = KEY_MATERIAL[rbx & 0xF]
        ts_byte = timestamp_bytes[rbx & 7]
        
        # XOR with running counters
        ecx = (key_byte ^ r13d) & 0xFFFFFFFF
        r13d = (r13d + 0xB) & 0xFFFFFFFF
        r8d = ecx & 0xFF
        
        eax = (ts_byte ^ r14d) & 0xFFFFFFFF
        r14d = (r14d + 0x11) & 0xFFFFFFFF
        r12d = eax
        
        # XOR with r10d
        r12d = (r12d ^ r10d) & 0xFFFFFFFF
        ecx = (ecx ^ r12d) & 0xFFFFFFFF
        
        r10d_temp = r12d & 0xFF
        ecx = ecx & 0xFF
        
        # Add edx and rotate
        ecx = rol32((ecx + edx) & 0xFFFFFFFF, 3)
        edx = ecx
        
        # Magic constant computation
        temp = rol32(((r8d + r10d_temp - 0x61C88647) & 0xFFFFFFFF) ^ r11d, 7)
        edx = edx ^ r11d
        
        r10d_temp = ((r10d_temp ^ edx) + r9d) & 0xFFFFFFFF
        r11d = (temp + r9d) & 0xFFFFFFFF
        rbx = (rbx + 1) & 0xF
        
        # Continue transformations
        r8d = ((r8d + r11d) ^ esi) & 0xFFFFFFFF
        r9d = rol32(r10d_temp, 11) ^ esi
        r8d = ror32(r8d, 13)
        esi = (edx + r8d) & 0xFFFFFFFF
        
        # Update r10d for next iteration
        if iteration < 15:
            r10d = KEY_MATERIAL[(iteration + 6) & 0xF]
    
    # Final computation
    counter_high = (counter >> 32) & 0xFFFFFFFF
    counter_low = counter & 0xFFFFFFFF
    
    result = edx ^ (counter_high ^ counter_low) ^ rol32(r11d, 5) ^ rol32(r9d, 13) ^ ror32(esi, 5)
    result = result ^ ((result >> 16) & 0xFFFF)
    return result % 1000000
```

### Service Interaction Script

We also created a complete solver that handles the POW challenge and OTP submission:

```python
#!/usr/bin/env python3
import socket
import time
import subprocess
import re

def solve_pow(pow_challenge):
    """Solve the proof-of-work challenge."""
    result = subprocess.run(
        ["curl", "-sSfL", "https://pwn.red/pow"],
        capture_output=True, text=True, timeout=10
    )
    script = result.stdout
    
    result = subprocess.run(
        ["bash", "-c", script, "-s", pow_challenge],
        capture_output=True, text=True, timeout=30
    )
    
    for line in result.stdout.split("\n"):
        if "solution:" in line:
            return line.split("solution:")[-1].strip()
    return None

def main():
    host = "challenge.hacktheflag.one"
    port = 30003
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))
    
    # Receive and solve POW
    data = sock.recv(4096).decode()
    pow_match = re.search(r"curl.*sh -s ([^\n]+)", data)
    if pow_match:
        solution = solve_pow(pow_match.group(1).strip())
        sock.send(f"{solution}\n".encode())
    
    # Generate and send OTP
    timestamp = int(time.time())
    counter = (timestamp // 30) - 1
    otp = generate_otp(counter)
    sock.send(f"{otp:06d}\n".encode())
    
    # Receive flag
    response = sock.recv(4096).decode()
    print(response)
```

---

## Verification

### Testing Against Known Values

Before connecting to the service, we verified our implementation against the GDB-extracted test cases:

```
Test Results:
  ✓ Counter 59158229: Expected 335019, Got 335019
  ✓ Counter 59158230: Expected 173188, Got 173188
  ✓ Counter 59158231: Expected 036154, Got 036154

All tests passed!
```

### Local Binary Testing

We also tested the OTP generation against the local binary to ensure compatibility:

```bash
# Run the binary and capture its behavior
./2fa_token_generator
```

The local binary accepted our generated OTPs, confirming the algorithm implementation was correct.

---

## Service Exploitation

### Connection Flow

1. **Connect** to `nc challenge.hacktheflag.one 30003`
2. **Receive** the proof-of-work challenge
3. **Solve** the POW using the pwn.red solver
4. **Receive** the timestamp prompt
5. **Generate** OTP for the current 30-second window
6. **Submit** the 6-digit code
7. **Receive** the decrypted flag

### Flag Extraction

Upon submitting a valid OTP, the service responded with:

```
[OK] Token accepted. Unlocking secured archive...
FLAG: FYPCTF26{seed_and_windows_are_all_you_need}
```

---

## Conclusion

### Key Takeaways

1. **Static Analysis First**: The `.rodata` section contained all the cryptographic material needed - no dynamic unpacking required.

2. **GDB Verification**: Dynamic analysis with GDB was crucial for extracting test cases to verify the reversed algorithm.

3. **Understanding the Loop Structure**: The most challenging aspect was understanding how the `r10d` register updated across iterations using a sliding window from the key material.

4. **Time Window Handling**: The algorithm tries three consecutive 30-second windows, making timing less critical.

### Tools Used

- `file` - Binary identification
- `strings` - String extraction
- `objdump` - Disassembly
- `gdb` - Dynamic analysis and debugging
- `nc` - Network connectivity testing
- Python 3 - Algorithm implementation and automation

### Flag

```
FYPCTF26{seed_and_windows_are_all_you_need}
```

The flag references both the embedded cryptographic **seed** material and the **time windows** used in the OTP generation algorithm - truly "all you need" to solve this challenge!

---

## Appendix: Complete Solver Script

```python
#!/usr/bin/env python3
"""
2FA Token Generator - Complete Solver
Implements the OTP generation algorithm reverse engineered from the binary.
"""

import socket
import time
import subprocess
import re

# Cryptographic data extracted from the binary at 0x2290
KEY_MATERIAL = bytes([
    0x42, 0x17, 0xA9, 0x5C, 0x33, 0xE1, 0x7F, 0x09,
    0xD4, 0x6B, 0x2E, 0x90, 0x1C, 0xF8, 0x55, 0xAB
])


def rol32(value, shift):
    """Rotate left 32-bit value."""
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def ror32(value, shift):
    """Rotate right 32-bit value."""
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def generate_otp(counter):
    """Generate OTP for a given counter value (timestamp // 30 - 1)."""
    timestamp_bytes = counter.to_bytes(8, 'little')
    
    # Initial state matching the binary
    r13d, r14d, rbx = 0x36, 0, 0
    r10d = 0xFFFFFFE1
    esi = 0x89ABCDEF
    r9d = 0x0F1E2D3C
    r11d = 0x2468ACE0
    edx = 0x13579BDF
    
    for iteration in range(16):
        key_byte = KEY_MATERIAL[rbx & 0xF]
        ts_byte = timestamp_bytes[rbx & 7]
        
        ecx = (key_byte ^ r13d) & 0xFFFFFFFF
        r13d = (r13d + 0xB) & 0xFFFFFFFF
        r8d = ecx & 0xFF
        
        eax = (ts_byte ^ r14d) & 0xFFFFFFFF
        r14d = (r14d + 0x11) & 0xFFFFFFFF
        r12d = eax
        
        r12d = (r12d ^ r10d) & 0xFFFFFFFF
        ecx = (ecx ^ r12d) & 0xFFFFFFFF
        
        r10d_temp = r12d & 0xFF
        ecx = ecx & 0xFF
        
        ecx = rol32((ecx + edx) & 0xFFFFFFFF, 3)
        edx = ecx
        
        temp = rol32(((r8d + r10d_temp - 0x61C88647) & 0xFFFFFFFF) ^ r11d, 7)
        edx = edx ^ r11d
        
        r10d_temp = ((r10d_temp ^ edx) + r9d) & 0xFFFFFFFF
        r11d = (temp + r9d) & 0xFFFFFFFF
        rbx = (rbx + 1) & 0xF
        
        r8d = ((r8d + r11d) ^ esi) & 0xFFFFFFFF
        r9d = rol32(r10d_temp, 11) ^ esi
        r8d = ror32(r8d, 13)
        esi = (edx + r8d) & 0xFFFFFFFF
        
        if iteration < 15:
            r10d = KEY_MATERIAL[(iteration + 6) & 0xF]
    
    counter_high = (counter >> 32) & 0xFFFFFFFF
    counter_low = counter & 0xFFFFFFFF
    
    result = edx ^ (counter_high ^ counter_low) ^ rol32(r11d, 5) ^ rol32(r9d, 13) ^ ror32(esi, 5)
    result = result ^ ((result >> 16) & 0xFFFF)
    return result % 1000000


if __name__ == "__main__":
    # Test against known values
    test_cases = [
        (59158229, 335019),
        (59158230, 173188),
        (59158231, 36154),
    ]
    
    print("Verifying OTP algorithm:")
    for counter, expected in test_cases:
        computed = generate_otp(counter)
        status = "✓" if computed == expected else "✗"
        print(f"  {status} Counter {counter}: {computed:06d}")
    
    # Generate current OTP
    timestamp = int(time.time())
    counter = (timestamp // 30) - 1
    otp = generate_otp(counter)
    print(f"\nCurrent timestamp: {timestamp}")
    print(f"Generated OTP: {otp:06d}")
```
