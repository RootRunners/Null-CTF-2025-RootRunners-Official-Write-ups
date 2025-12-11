# Concord Three — CTF Writeup (Updated Version)

## Initial Analysis (Updated)

Testing the bot with a normal spaced nickname (e.g., `Nomad Test`) results in the bot ignoring `!flag`.
From the challenge description:

> *“She hates spaces in display names.”*

So the first hypothesis is:

* The bot rejects any nickname containing the ASCII space `0x20`.

To verify this, various nicknames were used, including Unicode variants of whitespace.

### Using a Fullwidth Space

Discord supports the **fullwidth space** (U+3000), which visually resembles a normal space but is not the standard ASCII space.

The nickname used was:

```
Nomad　''.__class__.__mro__
```

Where the character between *Nomad* and *''.**class**.**mro*** is U+3000 (“IDEOGRAPHIC SPACE”).

This allowed:

* Maintaining the "look" of a spaced nickname.
* Bypassing the bot's naïve space filter, which only checks for `' '` (0x20).

### Why the `''.__class__.__mro__` part?

Including this suffix tests whether the bot:

* Performs dangerous string evaluation (e.g., `eval`, `ast.literal_eval`, template rendering).
* Is vulnerable to SSTI or Python object introspection.

In this challenge, it does **not** evaluate code — so the payload isn't executed.
However, it still **passes the validation check**, confirming the bypass.

Once the nickname was changed to that form, sending:

```
!flag
```

finally triggered the bot to reply with the correct flag.

---

## Exploitation

### Strategy

1. Identify that the bot blocks nicknames with ASCII spaces.
2. Replace spaces with a **fullwidth space (U+3000)**.
3. Optionally append a Python-class-poking payload to test for code evaluation:

   ```
   ''.__class__.__mro__
   ```
4. With the allowed nickname, send `!flag` and receive the flag.

### Example Implementation

Here is a helper snippet generating the *exact* bypass nickname style you used:

```python
FULLWIDTH_SPACE = "\u3000"

def build_nickname(base, payload):
    return base + FULLWIDTH_SPACE + payload

if __name__ == "__main__":
    nickname = build_nickname("Nomad", "''.__class__.__mro__")
    print("[+] Use this nickname in Discord:")
    print(nickname)
```

### Execution

```bash
$ python3 nickname_bypass.py
[+] Use this nickname in Discord:
Nomad　''.__class__.__mro__
```

In Discord:

```
!flag
```
→ Bot returns the flag.

---

pwned by **Nomad**
