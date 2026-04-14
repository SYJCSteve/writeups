# License Please 2 - Writeup

## Challenge Information
- **Name**: License Please 2
- **Category**: Reverse Engineering (REV)
- **Binary**: ELF 64-bit stripped PIE executable

## Summary
The challenge involves reverse engineering a license validation system that uses multi-layer policy checks and AES encryption. The binary expects a 32-character base36 uppercase activation code, validates it through multiple constraint layers, and decrypts an embedded ciphertext to reveal the flag.

## Flag
```
FYPCTF26{z3_solver_beats_enterprise_policies}
```

## Activation Code
```
Q7M4R2D9T8K1P5V3N6C0L4F2H9J7W3B1
```

## Solution Methodology

### 1. Binary Analysis
The binary is a stripped 64-bit ELF that:
1. Reads a 32-character activation code
2. Decodes it from base36 into 8 unsigned 32-bit integers
3. Validates the values through multiple policy layers
4. Derives an AES key from the validated values
5. Decrypts embedded ciphertext
6. Checks if the decrypted plaintext starts with "FYPCTF26{"

### 2. Key Findings from Disassembly

#### Memory Layout
The 8 decoded values are stored at these stack offsets:
- `v0` at `[rsp+0xa0]` (register: r15)
- `v1` at `[rsp+0xa4]` (register: ebp)
- `v2` at `[rsp+0xa8]` (register: r11)
- `v3` at `[rsp+0xac]` (register: r10)
- `v4` at `[rsp+0xb0]` (register: r13)
- `v5` at `[rsp+0xb4]` (register: r12)
- `v6` at `[rsp+0xb8]` (register: esi)
- `v7` at `[rsp+0xbc]` (register: ecx)

#### Value Range Constraint
Each decoded value must satisfy: `value <= 0x19a0ff` (1678591)

### 3. Policy Layer A Checks (First 3 Constraints)

**Check 1:** `7*v0 + 11*v1 + 13*v2 + 17*v3 ≡ 0x22bfb (mod 0xf4243)`

**Check 2:** `19*v4 + 23*v5 + 29*v6 + 31*v7 ≡ 0xf0c0c (mod 0xf4243)`

**Check 3:** `(v0 ^ v2 ^ v4 ^ v6) & 0xfffff == 0xa4cce`

### 4. Policy Layer B Checks (9 Additional Constraints)

**Check 4:** `(v1 + v3 + v5 + v7) & 0x3ffff == 0x31107`

**Check 5:** `((v0 << 1) ^ (v7 >> 1) ^ v3) & 0xffffff == 0x3fd7a9`

**Check 6:** `(v2 + v5) * (v1 - v4) == 0x489af983`

**Check 7:** `((v0 + v1 + v2) ^ (v5 + v6 + v7)) & 0x7fffff == 0x89284`

**Check 8:** `(v0 * v5) ^ (v2 * v7) == 0x10e79265`

**Check 9:** `rol(v0, 5) ^ rol(v1, 11) ^ v2 == 0x98641911`

**Check 10:** `rol(v3, 7) + rol(v4, 13) + v5 == 0x18fe0120`

**Check 11:** `(v7 ^ 0xa5a5a5a5) + v6 == 0xa5bfc79b`

**Check 12:** `(v6*v6 + v0*3 - v7*5) % 0x989693 == 0x74afd5`

### 5. Solving with Z3

The constraints form a system of equations that can be solved using Microsoft's Z3 SMT solver:

```python
from z3 import *

v = [BitVec(f'v{i}', 32) for i in range(8)]
s = Solver()

# Add all constraints (see solver_v6.py for complete list)
# ...

if s.check() == sat:
    model = s.model()
    values = [model[v[i]].as_long() for i in range(8)]
```

### 6. Solution Values

The solver found these valid values:
```
v0 = 1222924 (0x12a90c)  -> "Q7M4"
v1 = 1262781 (0x1344bd)  -> "R2D9"
v2 = 1364113 (0x14d091)  -> "T8K1"
v3 = 1173999 (0x11e9ef)  -> "P5V3"
v4 = 1081296 (0x107fd0)  -> "N6C0"
v5 = 985502  (0xf099e)   -> "L4F2"
v6 = 805507  (0xc4a83)   -> "H9J7"
v7 = 1497277 (0x16d8bd)  -> "W3B1"
```

### 7. Verification

Running the binary with the activation code:
```bash
$ echo "Q7M4R2D9T8K1P5V3N6C0L4F2H9J7W3B1" | ./license_please_2
=== Enterprise License Portal v2.4.1 ===
Enter offline activation code (32 chars, base36, uppercase):
Activation successful.
Flag: FYPCTF26{z3_solver_beats_enterprise_policies}
```

## Key Challenges

1. **Stripped Binary**: All function names and symbols were removed, requiring manual analysis
2. **Register Tracking**: Keeping track of which register holds which value was critical and error-prone
3. **Complex Constraints**: The interdependent constraints required an SMT solver to solve efficiently
4. **AES Encryption**: The binary uses AES encryption with a key derived from the validated values

## Tools Used
- `objdump` for disassembly
- Python with Z3 solver for constraint solving
- Custom Python scripts for verification

## Lessons Learned
- Careful register tracking is essential when reversing stripped binaries
- Z3 is extremely effective for solving constraint-based validation
- Always verify register mappings by tracing through the actual disassembly
- The order of operations and which values are used in each check is critical
