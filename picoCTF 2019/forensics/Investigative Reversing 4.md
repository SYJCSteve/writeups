# Investigative Reversing 4 - Writeup

## Challenge Information
- **Challenge Name**: Investigative Reversing 4
- **Category**: Forensics / Reverse Engineering
- **Files Provided**: 
  - `mystery` (ELF binary)
  - `Item01_cp.bmp` through `Item05_cp.bmp` (5 BMP image files)

---

## Summary

The challenge involves reverse engineering a binary that encodes a flag across 5 BMP image files using LSB (Least Significant Bit) steganography. The flag `picoCTF{N1c3_R3ver51ng_5k1115_000000000008c05144c}` is distributed across all 5 files, with each file containing 10 bytes of the 50-byte flag.

---

## Part 1: Initial Analysis

### File Identification

```bash
$ file mystery
mystery: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
         dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
         for GNU/Linux 3.2.0, not stripped

$ file Item0*_cp.bmp
Item01_cp.bmp: PC bitmap, Windows 3.x format, 1765 x 852 x 8
Item02_cp.bmp: PC bitmap, Windows 3.x format, 1765 x 852 x 8
Item03_cp.bmp: PC bitmap, Windows 3.x format, 1765 x 852 x 8
Item04_cp.bmp: PC bitmap, Windows 3.x format, 1765 x 852 x 8
Item05_cp.bmp: PC bitmap, Windows 3.x format, 1765 x 852 x 8
```

### Key Strings in Binary

```bash
$ strings mystery | grep -E "(flag|Item|\.bmp)"
flag.txt
Item01_cH
p.bmp
Item01.b
mp
```

The binary references:
- `flag.txt` - Source file containing the flag
- `Item01.bmp` through `Item05.bmp` - Input files (original images)
- `Item01_cp.bmp` through `Item05_cp.bmp` - Output files (encoded images)

---

## Part 2: Binary Reverse Engineering

### Identified Functions

Through disassembly (`objdump -d mystery`), three key functions were identified:

1. **`codedChar`** - Encodes a single bit into a byte's LSB
2. **`encodeDataInFile`** - Encodes flag data into a single BMP file
3. **`encodeAll`** - Orchestrates encoding across all 5 files

### The `codedChar` Function (0x7aa)

```asm
00000000000007aa <codedChar>:
 7aa:   push   %rbp
 7ab:   mov    %rsp,%rbp
 7ae:   mov    %edi,-0x14(%rbp)    # Argument: shift amount (bit position)
 7b1:   mov    %esi,%ecx
 7b3:   mov    %edx,%eax
 7b5:   mov    %ecx,%edx
 7b7:   mov    %dl,-0x18(%rbp)     # Argument: flag byte
 7ba:   mov    %al,-0x1c(%rbp)     # Argument: original byte from image
 7bd:   movb   $0x1,-0x1(%rbp)     # mask = 0x01
 7c1:   movb   $0xfe,-0x2(%rbp)    # clear_mask = 0xFE
 7c5:   cmpl   $0x0,-0x14(%rbp)
 7c9:   je     7db <codedChar+0x31>
 7cb:   movsbl -0x18(%rbp),%edx
 7cf:   mov    -0x14(%rbp),%eax
 7d2:   mov    %eax,%ecx
 7d4:   sar    %cl,%edx            # flag_byte >> shift
 7d6:   mov    %edx,%eax
 7d8:   mov    %al,-0x18(%rbp)
 7db:   movzbl -0x1(%rbp),%eax
 7df:   and    %al,-0x18(%rbp)     # bit = (flag_byte >> shift) & 1
 7e2:   movzbl -0x2(%rbp),%eax
 7e6:   and    %al,-0x1c(%rbp)     # original_byte & 0xFE (clear LSB)
 7e9:   movzbl -0x18(%rbp),%eax
 7ed:   or     %al,-0x1c(%rbp)     # result = (original_byte & 0xFE) | bit
 7f0:   movzbl -0x1c(%rbp),%eax    # Return encoded byte
 7f4:   pop    %rbp
 7f5:   ret
```

**Algorithm**: 
```c
byte codedChar(int shift, char flag_byte, char original_byte) {
    int bit = (flag_byte >> shift) & 1;
    return (original_byte & 0xFE) | bit;
}
```

### The `encodeDataInFile` Function (0x7f6)

This function handles the core encoding logic:

```asm
# Copy first 2019 (0x7e3) bytes verbatim
movl   $0x7e3,-0x24(%rbp)      # loop_count = 2019

# Main encoding loop (iterations 0-49)
movl   $0x0,-0xc(%rbp)         # iteration = 0
jmp    9b8 <encodeDataInFile+0x1c2>

# Check: if (iteration % 5 == 0)
mov    $0x66666667,%edx        # Magic number for division by 5
imul   %edx
sar    $1,%edx
sar    $0x1f,%eax
sub    %eax,%edx
shl    $0x2,%edx
add    %eax,%edx
sub    %edx,%eax
test   %eax,%eax
jne    982 <encodeDataInFile+0x18c>  # Skip encoding if not divisible by 5
```

**Key Findings**:
- First 2019 bytes are copied unchanged (BMP header + initial data)
- Loop runs for 50 iterations (0-49)
- Every 5th iteration (0, 5, 10, 15... 45): encode 8 bits of flag data
- Other iterations: copy 1 byte unchanged

### The `encodeAll` Function (0xa1a)

```asm
0000000000000a1a <encodeAll>:
  # Initialize output filename: "Item01_cp.bmp"
  movabs $0x635f31306d657449,%rax  # "Item0" + "1_c"
  movabs $0x706d622e70,%rdx        # "p.bmp"
  
  # Initialize input filename: "Item01.bmp"
  movabs $0x622e31306d657449,%rax  # "Item0" + "1.b"
  mov    $0x706d,%edx              # "mp"
  
  # Loop counter starts at '5' (0x35)
  movb   $0x35,-0x1(%rbp)          # file_number = '5'
  
  # Decrement and loop while file_number > '0'
  cmpb   $0x30,-0x1(%rbp)          # compare with '0'
  jg     a69 <encodeAll+0x4f>      # loop if greater
```

**Critical Discovery**: Files are processed in **reverse order: 5, 4, 3, 2, 1**

### The `main` Function (0xa9d)

```asm
0000000000000a9d <main>:
  # Allocate 50-byte buffer for flag
  lea    -0x40(%rbp),%rax
  mov    %rax,0x2015d1(%rip)       # flag buffer pointer
  
  # Initialize flag_index to 0
  movl   $0x0,-0x44(%rbp)
  lea    -0x44(%rbp),%rax
  mov    %rax,0x20159f(%rip)       # flag_index pointer
  
  # Open flag.txt
  lea    0xf8(%rip),%rsi           # "r" mode
  lea    0x128(%rip),%rdi          # "flag.txt"
  call   670 <fopen@plt>
  
  # Read up to 50 bytes (0x32)
  mov    $0x32,%esi                # read 50 bytes
  call   640 <fread@plt>
  
  # Call encodeAll
  call   a1a <encodeAll>
```

---

## Part 3: Encoding Algorithm Reconstruction

### Complete Encoding Flow

```
1. Read flag.txt into 50-byte buffer
2. Set flag_index = 0
3. For file_number in [5, 4, 3, 2, 1]:
   a. Open Item0{file_number}.bmp (input)
   b. Create Item0{file_number}_cp.bmp (output)
   c. Copy 2019 bytes verbatim
   d. For iteration in 0..49:
      - If iteration % 5 == 0:
         * Read 8 bytes from input
         * For shift in 0..7:
           - Encode bit: (flag[flag_index] >> shift) & 1
           - Write encoded byte to output
         * flag_index++
      - Else:
         * Copy 1 byte unchanged
   e. Copy remaining bytes until EOF
```

### Byte Position Calculation

Since every 5th iteration encodes 8 bytes:
- Start position: 2019 (after verbatim copy)
- Encoding positions: 2019, 2027, 2035, 2043, 2051, 2059, 2067, 2075, 2083, 2091
- Wait, actually the pattern is:
  - At iteration 0: encode 8 bytes (positions 2019-2026)
  - At iteration 1-4: copy 4 bytes (positions 2027-2030)
  - At iteration 5: encode 8 bytes (positions 2031-2038)
  - etc.

**Correct encoding byte ranges** (10 groups of 8 bytes each):
```
Group 0:  bytes 2019-2026  (encodes flag[0])
Group 1:  bytes 2031-2038  (encodes flag[1])
Group 2:  bytes 2043-2050  (encodes flag[2])
Group 3:  bytes 2055-2062  (encodes flag[3])
Group 4:  bytes 2067-2074  (encodes flag[4])
Group 5:  bytes 2079-2086  (encodes flag[5])
Group 6:  bytes 2091-2098  (encodes flag[6])
Group 7:  bytes 2103-2110  (encodes flag[7])
Group 8:  bytes 2115-2122  (encodes flag[8])
Group 9:  bytes 2127-2134  (encodes flag[9])
```

### Flag Distribution Across Files

| File | Flag Indices | Flag Content |
|------|-------------|--------------|
| Item05_cp.bmp | 0-9 | `picoCTF{N1` |
| Item04_cp.bmp | 10-19 | `c3_R3ver51` |
| Item03_cp.bmp | 20-29 | `ng_5k1115_` |
| Item02_cp.bmp | 30-39 | `0000000000` |
| Item01_cp.bmp | 40-49 | `08c05144c}` |

---

## Part 4: Extraction Methodology

### Decoding Algorithm

To decode, we reverse the encoding process:

1. For each BMP file, extract bytes at the 10 encoding positions
2. For each group of 8 bytes, extract the LSB from each byte
3. Combine the 8 bits into a single byte (LSB first)
4. Combine bytes from all files in processing order (5→4→3→2→1)

### Bit Extraction Formula

```python
def decode_byte(data, positions):
    """Extract one flag byte from 8 encoded bytes"""
    byte_val = 0
    for i, pos in enumerate(positions):
        bit = data[pos] & 0x01  # Extract LSB
        byte_val |= bit << i    # Combine bits (LSB first)
    return byte_val
```

### Complete Extraction Script

```python
#!/usr/bin/env python3
"""
Final decoder for Investigative Reversing 4
Extracts flag from 5 BMP files using LSB steganography

Encoding Algorithm (reverse engineered from 'mystery' binary):
1. Binary reads flag.txt into a 50-byte buffer
2. For each file Item01.bmp through Item05.bmp:
   - Copy 2019 bytes verbatim (BMP header)
   - For iterations 0-49:
     * If iteration % 5 == 0: encode 8 bits of one flag byte into 8 consecutive bytes
     * Else: copy 1 byte unchanged
3. Each file encodes 10 flag bytes (80 bytes with embedded data)
4. Files are processed in order 5→4→3→2→1, encoding flag bytes 0-49

Decoding: Extract LSB from encoding positions and combine bits
"""

import os

# Encoding byte ranges in each BMP file (10 groups of 8 bytes each)
ENCODING_GROUPS = [
    (2019, 2027),
    (2031, 2039),
    (2043, 2051),
    (2055, 2063),
    (2067, 2075),
    (2079, 2087),
    (2091, 2099),
    (2103, 2111),
    (2115, 2123),
    (2127, 2135),
]


def decode_file(filepath):
    """Extract 10 flag bytes from a single BMP file"""
    with open(filepath, "rb") as f:
        data = f.read()

    flag_bytes = []
    for start, end in ENCODING_GROUPS:
        byte_val = 0
        for i, pos in enumerate(range(start, end)):
            bit = data[pos] & 0x01  # Extract LSB
            byte_val |= bit << i  # Combine bits (LSB first)
        flag_bytes.append(byte_val)

    return bytes(flag_bytes)


def main():
    print("=" * 60)
    print("Investigative Reversing 4 - Flag Decoder")
    print("=" * 60)

    # Files are processed by encodeAll() in order: 5, 4, 3, 2, 1
    # So flag bytes are: file5(0-9), file4(10-19), file3(20-29), file2(30-39), file1(40-49)
    file_order = [5, 4, 3, 2, 1]

    flag_parts = {}
    print("\n[+] Decoding individual files:")
    for i in file_order:
        filepath = f"Item0{i}_cp.bmp"
        if os.path.exists(filepath):
            part = decode_file(filepath)
            flag_parts[i] = part
            print(f"    File {i}: {part.decode('latin-1')}")
        else:
            print(f"    [!] Missing: {filepath}")

    # Combine in processing order: 5, 4, 3, 2, 1
    print("\n[+] Combining flag parts in order 5→4→3→2→1:")
    full_flag = b"".join(flag_parts[i] for i in file_order)
    flag_str = full_flag.decode("latin-1")

    print(f"\n    Raw bytes: {full_flag}")
    print(f"    As string: {flag_str}")

    # Validate flag format
    print("\n[+] Validation:")
    print(f"    Starts with 'picoCTF{{': {flag_str.startswith('picoCTF{')}")
    print(f"    Ends with '}}': {flag_str.endswith('}')}")
    print(f"    Length: {len(flag_str)} bytes")

    # Extract clean flag (up to and including })
    if "}" in flag_str:
        clean_flag = flag_str[: flag_str.index("}") + 1]
        print(f"\n[***] FLAG: {clean_flag} [***]")
    else:
        print(f"\n[***] FLAG: {flag_str} [***]")


if __name__ == "__main__":
    main()
```

---

## Part 5: Verification

### Running the Extraction

```bash
$ python3 extract_flag.py
============================================================
Investigative Reversing 4 - Flag Decoder
============================================================

[+] Decoding individual files:
    File 5: picoCTF{N1
    File 4: c3_R3ver51
    File 3: ng_5k1115_
    File 2: 0000000000
    File 1: 08c05144c}

[+] Combining flag parts in order 5→4→3→2→1:

    Raw bytes: b'picoCTF{N1c3_R3ver51ng_5k1115_000000000008c05144c}'
    As string: picoCTF{N1c3_R3ver51ng_5k1115_000000000008c05144c}

[+] Validation:
    Starts with 'picoCTF{': True
    Ends with '}': True
    Length: 50 bytes

[***] FLAG: picoCTF{N1c3_R3ver51ng_5k1115_000000000008c05144c} [***]
```

### Byte-Level Verification

| Position | Hex  | Char | Source File |
|----------|------|------|-------------|
| 0 | 0x70 | p | Item05 |
| 1 | 0x69 | i | Item05 |
| 2 | 0x63 | c | Item05 |
| 3 | 0x6f | o | Item05 |
| 4 | 0x43 | C | Item05 |
| 5 | 0x54 | T | Item05 |
| 6 | 0x46 | F | Item05 |
| 7 | 0x7b | { | Item05 |
| 8 | 0x4e | N | Item05 |
| 9 | 0x31 | 1 | Item05 |
| 10 | 0x63 | c | Item04 |
| 11 | 0x33 | 3 | Item04 |
| 12 | 0x5f | _ | Item04 |
| 13 | 0x52 | R | Item04 |
| 14 | 0x33 | 3 | Item04 |
| 15 | 0x76 | v | Item04 |
| 16 | 0x65 | e | Item04 |
| 17 | 0x72 | r | Item04 |
| 18 | 0x35 | 5 | Item04 |
| 19 | 0x31 | 1 | Item04 |
| 20 | 0x6e | n | Item03 |
| 21 | 0x67 | g | Item03 |
| 22 | 0x5f | _ | Item03 |
| 23 | 0x35 | 5 | Item03 |
| 24 | 0x6b | k | Item03 |
| 25 | 0x31 | 1 | Item03 |
| 26 | 0x31 | 1 | Item03 |
| 27 | 0x31 | 1 | Item03 |
| 28 | 0x35 | 5 | Item03 |
| 29 | 0x5f | _ | Item03 |
| 30-39 | 0x30 | 0 | Item02 |
| 40 | 0x30 | 0 | Item01 |
| 41 | 0x38 | 8 | Item01 |
| 42 | 0x63 | c | Item01 |
| 43 | 0x30 | 0 | Item01 |
| 44 | 0x35 | 5 | Item01 |
| 45 | 0x31 | 1 | Item01 |
| 46 | 0x34 | 4 | Item01 |
| 47 | 0x34 | 4 | Item01 |
| 48 | 0x63 | c | Item01 |
| 49 | 0x7d | } | Item01 |

---

## Part 6: Key Insights

### Why This Challenge Is Interesting

1. **Distributed Encoding**: Unlike typical steganography where the entire message is in one file, this challenge splits the flag across 5 files.

2. **Reverse Processing Order**: The binary processes files in reverse order (5→4→3→2→1), which is a subtle detail that could trip up analysis.

3. **Modulo-Based Encoding**: The `iteration % 5 == 0` check creates a specific pattern that required identifying the exact byte positions.

4. **Bit-Level LSB**: Each flag byte is split into 8 individual bits, each stored in a different byte's LSB.

### Tools Used

- `file` - Initial file identification
- `strings` - String extraction from binary
- `objdump -d` - Disassembly of the binary
- Python 3 - Custom decoder implementation

---

## Final Flag

```
picoCTF{N1c3_R3ver51ng_5k1115_000000000008c05144c}
```

---

## References

- Challenge: picoCTF 2019 - Investigative Reversing 4
- Binary: `mystery` (ELF 64-bit, not stripped)
- Images: 5 BMP files (1765x852, 8-bit depth)
