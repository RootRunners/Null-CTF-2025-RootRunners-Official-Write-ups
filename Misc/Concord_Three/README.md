# Concord Three – CTF Writeup

## Challenge Information

| Field              | Value                                                                                                                |
| ------------------ | -------------------------------------------------------------------------------------------------------------------- |
| **CTF**            | NullCTF                                                                                                              |
| **Category**       | Misc                                                                                                                 |
| **Difficulty**     | Medium                                                                                                               |
| **Points**         | 477                                                                                                                  |
| **Challenge Link** | [https://ctf.r0devnull.team/challenges#Concord%20Three-21](https://ctf.r0devnull.team/challenges#Concord%20Three-21) |

## Description

> Concord Three
> 477
> misc discord medium
> Author: Stefan
>
> Not so tough this time! Evil Twin has been (hopefully!) defeated, but Good Twin still stands. A lot of people have been spamming "!flag" in the server, hoping to actually get one. Can you find out if the Good Twin lied to us or if it really does give out flags? PS: She hates spaces in display names.

**Files provided:**

* None

**Flag format:** `nullctf{.*}`

---

## TL;DR

Good Twin only responds to `!flag` inside a **temporary ticket channel** created through the bot.
However, it refuses to talk to users with **spaces** in their display name.
By bypassing the filter using a **fullwidth space (U+3000)**, the bot accepts the username and returns the flag.

**Vulnerability:** Unicode space filter bypass
**Approach:** Use a fullwidth space in the Discord nickname to evade the bot’s “no spaces allowed” rule.

---

## Initial Analysis

### Reconnaissance on the Discord bot

First we tested the bot in the main Discord server.
Typing `!flag` in public channels resulted in nothing—no error, no response.
This hinted at a possible permission or context restriction.

After exploring the server’s structure, we noticed a bot feature allowing users to create **temporary ticket channels**. Once created, the bot enters the channel directly, suggesting that commands must be issued from inside it.

Inside the ticket channel, executing:

```
!flag
```

finally triggered a response—a URL such as:

```
http://public.ctf.r0devnull.team:3888/?hello=0.8421638273645358&username=Nomad_0_o
```

Visiting the link displayed:

```
Hello Nomad_0_o! 👋
```

However, when using a display name with **spaces**, the bot changed the username parameter to:

```
Nomad_your_name_had_a_space_so_i_used_dotreplace_flag
```

**Key observations:**

* The bot ignores `!flag` unless inside a temporary ticket channel.
* The bot *hates ASCII spaces* in display names.
* If your nickname contains a space, the bot replaces it with `_your_name_had_a_space...`.

---

## Web Analysis

### Understanding the username filter

Testing different nicknames revealed that the bot rejects or mangles only **ASCII spaces** (`0x20`), but does not handle Unicode whitespace.

The goal became:
**Find a “space-like” character that Discord allows but the bot does not treat as a real space.**

### Trying Unicode alternatives

The breakthrough came with the **fullwidth space (U+3000)**, visually similar to a space but not ASCII.

The nickname used:

```
Nomad　''.__class__.__mro__
```

Notes:

* The character between *Nomad* and *''.**class**…* is **U+3000**, not a real space.
* The Python-like suffix was used to test for potential template injection (the challenge did not evaluate it, but it remained harmless).

With this nickname, the bot accepted the username normally.

---

## Exploitation

### Strategy

1. Create a **temporary ticket channel** via the bot’s interface.
   Good Twin only responds there.
2. Change your Discord display name to include a **fullwidth space** instead of a normal space:

   ```
   Nomad　''.__class__.__mro__
   ```
3. Inside the ticket channel, run:

   ```
   !flag
   ```
4. Visit the generated URL and retrieve the flag.

### Implementation

Below is a simple script that generates the exact nickname payload:

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

After setting the nickname and using `!flag` inside the temporary ticket channel:

```
[+] Bot return flag!
```

---

pwn by **Nomad**
