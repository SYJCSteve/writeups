# Investigative Reversing 0 - CTF Writeup

## Challenge Overview

- **Challenge Name:** Investigative Reversing 0  
- **Category:** Forensics  

### Description
We have recovered a binary and an image. See what you can make of it. There should be a flag somewhere.

### Files Provided
- `mystery` - A binary/executable file
- `mystery.png` - A PNG image file

---

## Initial Analysis

First, let's identify what types of files we're working with:

```bash
$ file mystery mystery.png
mystery:     ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=34b772a4f30594e2f30ac431c72667c3e10fa3e9, not stripped
mystery.png: PNG image data, 1411 x 648, 8-bit/color RGB, non-interlaced
```

We have:
1. A 64-bit ELF executable (not stripped - good for analysis)
2. A PNG image file

---

## Step-by-Step Solution

### Step 1: Analyze the Binary with `strings`

Before diving into disassembly, let's check for readable strings in the binary:

```bash
$ strings mystery | head -50
```

**Key findings from strings output:**
- References to `flag.txt` - The binary expects a flag file as input
- References to `mystery.png` - The binary outputs to this PNG file
- Messages like "No flag found, please make sure this is run on the server"
- The string "at insert" suggesting the binary inserts data somewhere

This tells us the binary reads from `flag.txt` and writes encoded data to `mystery.png`.

### Step 2: Check the PNG for Anomalies

Let's examine the PNG file for any unusual data or appended content:

```bash
$ exiftool mystery.png
```

**Output:**
```
ExifTool Version Number         : 13.50
File Name                       : mystery.png
...
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 1411x648
...
```

**Critical Finding:** The warning "Trailer data after PNG IEND chunk" indicates there's hidden data appended after the end of the PNG file!

### Step 3: Examine the PNG Trailer

Let's look at the end of the PNG file to see the hidden data:

```bash
$ hexdump -C mystery.png | tail -20
```

**Output:**
```
0001e860  ed 5a 9d 38 d0 1f 56 00  00 00 00 49 45 4e 44 ae  |.Z.8..V....IEND.|
0001e870  42 60 82 70 69 63 6f 43  54 4b 80 6b 35 7a 73 69  |B`.picoCTK.k5zsi|
0001e880  64 36 71 5f 33 30 33 64  36 61 65 62 7d           |d6q_303d6aeb}|
```

We can see:
- `IEND` at offset `0x1e86b` - marks the end of the PNG image data
- `ae 42 60 82` - the PNG file signature trailer (CRC for IEND)
- After the trailer: `70 69 63 6f 43 54 4b 80 6b 35 7a 73 69 64 36 71 5f 33 30 33 64 36 61 65 62 7d`

This hidden data (26 bytes) appears to be: `picoCTK\x80k5zsid6q_303d6aeb}`

### Step 4: Disassemble the Binary to Understand the Encoding

To decode the flag, we need to understand how the binary encoded it. Let's disassemble the binary:

```bash
$ objdump -d mystery
```

Looking at the `main` function (address `0x1195`), we can identify the encoding logic:

```asm
# First 6 bytes are written as-is (indices 0-5)
123c: 0f b6 45 d0           movzbl -0x30(%rbp),%eax    # Load byte at index 0
...
12b9: 0f b6 45 d5           movzbl -0x2b(%rbp),%eax    # Load byte at index 5

# Loop for bytes 6-13: ADD 5 to each byte
12d2: c7 45 b4 06 00 00 00  movl   $0x6,-0x4c(%rbp)    # Counter = 6
12db: 8b 45 b4              mov    -0x4c(%rbp),%eax    # Load counter
12de: 48 98                 cltq
12e0: 0f b6 44 05 d0        movzbl -0x30(%rbp,%rax,1),%eax  # Load byte at index
12e5: 88 45 b3              mov    %al,-0x4d(%rbp)
12e8: 0f b6 45 b3           movzbl -0x4d(%rbp),%eax
12ec: 83 c0 05              add    $0x5,%eax           # ADD 5!
12ef: 88 45 b3              mov    %al,-0x4d(%rbp)
1304: 83 45 b4 01           addl   $0x1,-0x4c(%rbp)    # Counter++
1308: 83 7d b4 0e           cmpl   $0xe,-0x4c(%rbp)    # Compare to 14
130c: 7e cd                 jle    12db <main+0x146>   # Loop if <= 14

# Byte 14: SUBTRACT 3
130e: 0f b6 45 df           movzbl -0x21(%rbp),%eax    # Load byte at index 14
1319: 83 e8 03              sub    $0x3,%eax           # SUBTRACT 3!

# Bytes 15-25: written as-is
1331: c7 45 b8 10 00 00 00  movl   $0x10,-0x48(%rbp)   # Counter = 16
```

### Step 5: Understand the Encoding Scheme

From the disassembly, the encoding scheme is:

| Byte Indices | Operation | To Decode |
|--------------|-----------|-----------|
| 0-5 | No change | Use as-is |
| 6-13 | Add 5 | Subtract 5 |
| 14 | Subtract 3 | Add 3 |
| 15-25 | No change | Use as-is |

### Step 6: Extract and Decode the Flag

Let's write a Python script to extract and decode the hidden flag:

```python
# Read the PNG file
with open('mystery.png', 'rb') as f:
    data = f.read()

# Find IEND chunk
iend_pos = data.find(b'IEND')

# Hidden data starts after IEND chunk:
# - 4 bytes: chunk length (before IEND)
# - 4 bytes: chunk type ("IEND")  
# - 0 bytes: chunk data
# - 4 bytes: CRC
# Total: 12 bytes from length to end of CRC
hidden_start = iend_pos + 8  # After "IEND" (4) + CRC (4) = 8 bytes from IEND position

# Extract 26 bytes of hidden data (0x1a = 26, as seen in fread call)
hidden_data = data[hidden_start:hidden_start + 26]

print(f"Hidden data (hex): {hidden_data.hex()}")
print(f"Hidden data: {hidden_data}")

# Decode the flag
decoded = bytearray()
for i, b in enumerate(hidden_data):
    if i < 6:
        # Bytes 0-5: as-is
        decoded.append(b)
    elif i < 14:
        # Bytes 6-13: subtract 5 (reverse of adding 5)
        decoded.append((b - 5) & 0xff)
    elif i == 14:
        # Byte 14: add 3 (reverse of subtracting 3)
        decoded.append((b + 3) & 0xff)
    else:
        # Bytes 15-25: as-is
        decoded.append(b)

print(f"Decoded flag: {decoded.decode()}")
```

**Output:**
```
Hidden data (hex): 7069636f43544b806b357a73696436715f33303364366165627d
Hidden data: b'picoCTK\x80k5zsid6q_303d6aeb}'
Decoded flag: picoCTF{f0und_9q_303d6aeb}
```

### Step 7: Verification

Let's verify the decoding by checking each byte:

| Index | Encoded (hex) | Encoded (char) | Operation | Decoded (hex) | Decoded (char) |
|-------|---------------|----------------|-----------|---------------|----------------|
| 0 | 0x70 | p | as-is | 0x70 | p |
| 1 | 0x69 | i | as-is | 0x69 | i |
| 2 | 0x63 | c | as-is | 0x63 | c |
| 3 | 0x6f | o | as-is | 0x6f | o |
| 4 | 0x43 | C | as-is | 0x43 | C |
| 5 | 0x54 | T | as-is | 0x54 | T |
| 6 | 0x4b | K | - 5 | 0x46 | F |
| 7 | 0x80 | \x80 | - 5 | 0x7b | { |
| 8 | 0x6b | k | - 5 | 0x66 | f |
| 9 | 0x35 | 5 | - 5 | 0x30 | 0 |
| 10 | 0x7a | z | - 5 | 0x75 | u |
| 11 | 0x73 | s | - 5 | 0x6e | n |
| 12 | 0x69 | i | - 5 | 0x64 | d |
| 13 | 0x64 | d | - 5 | 0x5f | _ |
| 14 | 0x36 | 6 | + 3 | 0x39 | 9 |
| 15 | 0x71 | q | as-is | 0x71 | q |
| 16 | 0x5f | _ | as-is | 0x5f | _ |
| 17 | 0x33 | 3 | as-is | 0x33 | 3 |
| 18 | 0x30 | 0 | as-is | 0x30 | 0 |
| 19 | 0x33 | 3 | as-is | 0x33 | 3 |
| 20 | 0x64 | d | as-is | 0x64 | d |
| 21 | 0x36 | 6 | as-is | 0x36 | 6 |
| 22 | 0x61 | a | as-is | 0x61 | a |
| 23 | 0x65 | e | as-is | 0x65 | e |
| 24 | 0x62 | b | as-is | 0x62 | b |
| 25 | 0x7d | } | as-is | 0x7d | } |

---

## Flag

```
picoCTF{f0und_9q_303d6aeb}
```

---

## Key Learnings

### Techniques Used

1. **File Type Identification**: Using `file` command to understand what we're working with
2. **String Analysis**: Using `strings` to find readable text and hints in binaries
3. **Metadata Analysis**: Using `exiftool` to check for anomalies in image files
4. **Hex Dump Analysis**: Using `hexdump -C` to examine binary data at the byte level
5. **Static Analysis**: Disassembling the binary with `objdump` to understand the encoding algorithm
6. **Data Extraction**: Writing Python scripts to extract and process hidden data
7. **Reverse Engineering**: Understanding and reversing the custom encoding scheme

### Important Concepts

1. **PNG File Structure**: 
   - PNG files end with an `IEND` chunk
   - The IEND chunk has a specific structure: 4-byte length + 4-byte type + 0-byte data + 4-byte CRC
   - Data can be appended after the PNG trailer without affecting image rendering

2. **Binary Analysis**:
   - Unstripped binaries contain symbol information that makes analysis easier
   - `objdump -d` provides assembly code that reveals program logic
   - Looking for loops and arithmetic operations can reveal encoding schemes

3. **Custom Encoding**:
   - The challenge used a position-dependent encoding scheme
   - Different byte ranges had different transformations applied
   - Understanding the forward encoding allowed us to reverse it

### Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify file types |
| `strings` | Extract readable text from binaries |
| `exiftool` | Check image metadata and anomalies |
| `hexdump -C` | View binary data in hex and ASCII |
| `objdump -d` | Disassemble binary to assembly code |
| Python | Extract and decode hidden data |

### Prevention Tips (for defenders)

- Be aware that data can be hidden after file format trailers
- Use tools like `binwalk` or `foremost` to scan for appended data
- Check file sizes - unusually large files may contain hidden data
- Always analyze both the structure and content of recovered files

---

## Alternative Approaches

1. **Using binwalk**:
   ```bash
   binwalk -e mystery.png
   ```
   This would extract any data appended to the PNG.

2. **Using dd to extract trailer**:
   ```bash
   # Calculate offset after IEND CRC
   dd if=mystery.png of=hidden_data.bin bs=1 skip=125043
   ```

3. **Using xxd with offset**:
   ```bash
   xxd -s 125043 mystery.png
   ```

---

*Writeup created for educational purposes. Challenge from picoCTF.*
