# Invisible WORDs - CTF Writeup

## Challenge Information
- **Name**: Invisible WORDs
- **Category**: Forensics
- **Difficulty**: Medium
- **Flag**: `picoCTF{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_a23dfbd4}`

## Description
The challenge provides a BMP image (`output.bmp`) and a hint about "cyberpunk baddies" and "AI art generators". The description also mentions that the suspect is "trafficking in classics," which hints at the content of the hidden data.

## Initial Analysis
The provided file is `output.bmp`, a 32-bit BMP image. 

1.  **File Identification**:
    ```bash
    file output.bmp
    # output.bmp: PC bitmap, Windows 98/2000 and newer format, 960 x 540 x 32, cbSize 2073738, bits offset 138
    ```
    The image is 960x540 with 32 bits per pixel (RGBA or similar).

2.  **Hex Inspection**:
    Inspecting the beginning of the pixel data (offset `0x8a` as indicated by the header):
    ```bash
    hexdump -C output.bmp | head -n 20
    ```
    At offset `0x8a`, we see:
    ```
    00000080  00 00 00 00 00 00 00 00  00 00 38 67 50 4b 95 52  |..........8gPK.R|
    00000090  03 04 c6 18 14 00 ce 3d  00 00 10 4a 08 00 6f 56  |.......=...J..oV|
    ```
    Notice the bytes `50 4b 03 04` starting at `0x8c`. This is the magic header for a ZIP file. However, they are interleaved with other bytes.

3.  **Interleaving Pattern**:
    Looking closer at the 4-byte pixel structure:
    - Pixel 1 (starts at `0x8a`): `38 67 50 4b`
    - Pixel 2 (starts at `0x8e`): `95 52 03 04`
    - Pixel 3 (starts at `0x92`): `c6 18 14 00`
    
    The ZIP header `50 4b 03 04` is formed by taking the 3rd and 4th bytes of each 4-byte pixel.
    - Pixel 1: `[38 67] [50 4b]` -> `50 4b`
    - Pixel 2: `[95 52] [03 04]` -> `03 04`
    
    This suggests that the image uses a 16-bit color format (likely 5-5-5 or similar) stored in a 32-bit container, leaving the upper 16 bits (2 bytes) of each pixel available for steganography.

## Exploitation/Analysis Methodology

### 1. Extraction Script
A Python script was written to iterate through the pixel data and extract the 3rd and 4th bytes of every 4-byte word.

```python
import sys

with open('output.bmp', 'rb') as f:
    data = f.read()

# Pixel data starts at 0x8a (from BMP header)
pixel_data = data[0x8a:]

hidden_data = bytearray()
for i in range(0, len(pixel_data), 4):
    # Extract the 3rd and 4th bytes of each 4-byte pixel
    hidden_data.extend(pixel_data[i+2:i+4])

with open('hidden.zip', 'wb') as f:
    f.write(hidden_data)
```

### 2. Decompression
After running the script, the resulting `hidden.zip` was extracted:
```bash
7z x hidden.zip
```
This produced a file named `ZnJhbmtlbnN0ZWluLXRlc3QudHh0`. The filename itself is base64 encoded: `echo "ZnJhbmtlbnN0ZWluLXRlc3QudHh0" | base64 -d` results in `frankenstein-test.txt`.

### 3. Finding the Flag
Searching the extracted text file for the flag:
```bash
grep -i "picoCTF" ZnJhbmtlbnN0ZWluLXRlc3QudHh0
```
Output:
`At that age I became acquainted with the celebrated picoCTF{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_a23dfbd4}`

## Conclusion
The challenge used a common steganography technique where data is hidden in unused or less significant bits of an image format. In this case, a 32-bit BMP was used to store 16-bit color data, leaving 16 bits per pixel for a hidden ZIP archive containing the flag embedded within a classic literary text (Frankenstein).
