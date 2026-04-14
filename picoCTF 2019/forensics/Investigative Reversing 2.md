# Investigative Reversing 2 - CTF Writeup

**Challenge:** Investigative Reversing 2  
**Category:** Forensics (with Reverse Engineering)  
**Files Provided:** `mystery`, `encoded.bmp`  

**Flag:** `picoCTF{n3xt_0n300000000000000000000000009e6b130d}`

---

## Summary

This challenge involves recovering a hidden flag from a BMP image using reverse engineering. We are given a binary (`mystery`) and an encoded image (`encoded.bmp`). The binary is a steganography encoder that embeds flag characters into the least significant bits (LSB) of pixel bytes. By reverse engineering the encoding algorithm from the binary, we can extract the flag from the provided image.

---

## Initial Analysis

### File Identification

First, let's identify what we're working with:

```bash
$ file mystery encoded.bmp
mystery:     ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
encoded.bmp: PC bitmap, Windows 3.x format, 1765 x 852 x 8

$ ls -la
-rwxr-xr-x 1 user user   16824 Mar 17 10:00 mystery
-rw-r--r-- 1 user user 1507414 Mar 17 10:00 encoded.bmp
```

We have:
- A 64-bit ELF executable compiled with GCC
- An 8-bit uncompressed BMP image (1.5 MB)

### String Analysis

Running `strings` on the binary reveals important clues:

```bash
$ strings mystery | grep -E "(flag|bmp|original|encode)"
flag.txt
original.bmp
encoded.bmp
No flag found, please make sure this is run on the server
original.bmp is missing, please run this on the server
flag is not 50 chars
codedChar
```

Key observations:
1. The binary expects `flag.txt` and `original.bmp` as inputs
2. It outputs `encoded.bmp`
3. The flag is exactly 50 characters
4. There's a function called `codedChar` that likely handles the encoding

---

## Binary Reverse Engineering

### Identifying Key Functions

Using `objdump` to examine the binary:

```bash
$ objdump -d mystery | grep -A 5 "codedChar>"
0000000000001195 <codedChar>:
    1195:   55                      push   %rbp
    1196:   48 89 e5                mov    %rsp,%rbp
    1199:   48 83 ec 30             sub    $0x30,%rsp
    ...
```

The `codedChar` function is at address `0x1195`.

### Analyzing the codedChar Function

Disassembling the `codedChar` function reveals the encoding algorithm:

```asm
codedChar:
    push   %rbp
    mov    %rsp,%rbp
    sub    $0x30,%rsp
    mov    %edi,-0x24(%rbp)      # shift parameter
    mov    %esi,-0x28(%rbp)      # flag_byte parameter  
    mov    %edx,-0x2c(%rbp)      # pixel_byte parameter
    movb   $0x1,-0x2(%rbp)       # mask1 = 0x01
    movb   $0xfe,-0x1(%rbp)      # mask2 = 0xFE
    mov    -0x28(%rbp),%eax
    mov    %eax,%edx
    mov    -0x24(%rbp),%eax
    mov    %eax,%ecx
    sar    %cl,%edx              # shift right by 'shift' amount
    mov    %edx,%eax
    and    -0x2(%rbp),%eax       # AND with 0x01 (keep LSB)
    mov    %al,-0x14(%rbp)       # store result
    mov    -0x2c(%rbp),%eax
    and    -0x1(%rbp),%eax       # AND with 0xFE (clear LSB)
    mov    %eax,%edx
    or     -0x14(%rbp),%edx      # OR with flag bit
    mov    %eax,-0x2c(%rbp)
    mov    -0x2c(%rbp),%eax
    leave
    ret
```

### Decoding the Algorithm

From the disassembly, the encoding algorithm is:

```c
char codedChar(int shift, char flag_byte, char pixel_byte) {
    char mask1 = 0x01;  // Extract single bit
    char mask2 = 0xFE;  // Clear LSB (11111110)
    
    // Shift flag_byte right by 'shift' positions
    char shifted = flag_byte >> shift;
    
    // Keep only the LSB after shifting
    char flag_bit = shifted & mask1;
    
    // Clear LSB of pixel and set it to flag_bit
    char result = (pixel_byte & mask2) | flag_bit;
    
    return result;
}
```

**Encoding formula:**
```
encoded_byte = (original_pixel & 0xFE) | ((flag_byte >> shift) & 0x01)
```

### Main Function Analysis

The main function reveals how the encoding is applied:

```asm
; Read 50 bytes from flag.txt
mov    $0x32,%esi              # 50 bytes
...
call   fread@plt

; Copy 2000 bytes header from original.bmp
movl   $0x7d0,-0x60(%rbp)      # 2000 = 0x7D0
...

; Encoding loop for each flag character
; for (i = 0; i < 50; i++) {
;     for (shift = 0; shift < 8; shift++) {
;         byte = codedChar(shift, flag[i]-5, original_pixel);
;         write(encoded.bmp, byte);
;     }
; }
```

Key findings:
1. First 2000 bytes are copied directly (BMP header)
2. Each flag character is encoded into 8 consecutive pixel bytes
3. For each bit position 0-7, that bit is extracted from `(flag_char - 5)`
4. The bit is stored in the LSB of each pixel byte

---

## Decoding Strategy

Since we only have `encoded.bmp` (not `original.bmp`), we need to reverse the encoding:

1. **Skip the header**: First 2000 bytes are unchanged BMP header
2. **Extract LSBs**: For each flag character, read 8 consecutive bytes and extract their LSBs
3. **Reconstruct bytes**: Combine the 8 bits to form the encoded flag byte
4. **Reverse the offset**: Add 5 to each byte to get the original character

**Decoding formula:**
```
flag_byte = (bit0 << 0) | (bit1 << 1) | (bit2 << 2) | ... | (bit7 << 7)
flag_char = flag_byte + 5
```

---

## Exploitation / Solution Script

### Decoder Implementation

```python
#!/usr/bin/env python3
"""
Decoder for Investigative Reversing 2 steganography challenge.

Encoding algorithm (from codedChar function):
- encoded_byte = (orig_byte & 0xFE) | ((flag_byte >> shift) & 0x01)
- Where shift ranges from 0 to 7
- flag_byte is actually (flag_char - 5)

Decoding:
- Each flag character is encoded in 8 consecutive bytes (bits 0-7)
- Extract LSB from each encoded byte and reconstruct the flag byte
- Add 5 to get the original flag character
"""


def decode_flag(encoded_bmp_path, offset=2000, flag_len=50):
    with open(encoded_bmp_path, "rb") as f:
        data = f.read()

    flag = []

    for char_idx in range(flag_len):
        flag_byte = 0
        for bit_pos in range(8):
            # Get the byte position in the encoded BMP
            byte_pos = offset + (char_idx * 8) + bit_pos
            encoded_byte = data[byte_pos]

            # Extract LSB (the encoded bit)
            bit = encoded_byte & 0x01

            # Reconstruct the flag byte (shift was bit_pos)
            flag_byte |= bit << bit_pos

        # Reverse the -5 operation from encoding
        flag_char = chr(flag_byte + 5)
        flag.append(flag_char)

    return "".join(flag)


if __name__ == "__main__":
    flag = decode_flag("encoded.bmp")
    print(f"Flag: {flag}")
```

### Running the Decoder

```bash
$ python3 decoder.py
Flag: picoCTF{n3xt_0n300000000000000000000000009e6b130d}
```

---

## Verification

Let's manually verify the first character to confirm our understanding:

```python
# First 8 bytes at offset 2000 in encoded.bmp
data = open('encoded.bmp', 'rb').read()
first_8 = data[2000:2008]
print(f"First 8 bytes: {first_8.hex()}")
# Output: e9e9e8e9e8e9e9e8

# Extract LSBs
lsbs = [b & 0x01 for b in first_8]
print(f"LSBs: {lsbs}")
# Output: [1, 1, 0, 1, 0, 1, 1, 0]

# Reconstruct byte (note: shift was 0-7, so bit order is correct)
flag_byte = sum(bit << pos for pos, bit in enumerate(lsbs))
print(f"Reconstructed byte: {flag_byte} (0x{flag_byte:02x})")
# Output: 107 (0x6b)

# Add 5 to reverse encoding
original = flag_byte + 5
print(f"Original char: {chr(original)} (ASCII {original})")
# Output: p (ASCII 112)
```

The first character is 'p', which matches the expected flag format `picoCTF{...}`.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify file types |
| `strings` | Extract readable strings from binary |
| `objdump -d` | Disassemble binary |
| `readelf` | Examine ELF structure |
| Python | Write decoder script |
| `xxd` | Hex dump for verification |

---

## Key Takeaways

1. **LSB Steganography**: The challenge demonstrates classic LSB steganography where data is hidden in the least significant bits of image pixels.

2. **Bit-level Encoding**: Each flag byte was spread across 8 pixel bytes, with one bit per byte.

3. **Simple Obfuscation**: The `-5` offset is a simple obfuscation technique that needed to be reversed.

4. **Binary Analysis**: Understanding the `codedChar` function was crucial - it showed exactly how data was encoded.

5. **Header Preservation**: The first 2000 bytes were copied unchanged, indicating where the encoded data begins.

---

## Flag

```
picoCTF{n3xt_0n300000000000000000000000009e6b130d}
```
