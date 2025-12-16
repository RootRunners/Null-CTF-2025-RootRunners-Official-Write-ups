# Reservation

| Category | Misc |
| Points | 50 |
| Difficulty | Easy |
| Author | Stefan |

## Challenge Description

> I wanted to take my inexistent girlfriend to this fancy restaurant called Windows, but they keep asking me for a key PROMPT. I don't know what to do, can you help me?

## Challenge Overview

We need to connect to a remote server and provide the correct passphrase to retrieve the flag. The server is themed around a Windows command prompt and drops hints about what we need to find.

### Server Response after making connection

```
[windows_10 | cmd.exe] Welcome good sire to our fine establishment.
Unfortunately, due to increased demand,
we have had to privatize our services.
Please enter the secret passphrase received from the environment to continue.
```

## Source Code Analysis

The challenge provides `reservation.py`:

```python
PROMPT = os.getenv("PROMPT", "bananananannaanan")
```

Key observations:
- The server reads the `PROMPT` environment variable
- The banner displays `[windows_10 | cmd.exe]` — a clear Windows reference
- If `PROMPT` isn't set, it defaults to `"bananananannaanan"`

## Solution

### Understanding Windows Prompts

On Windows systems, the `PROMPT` environment variable controls how the command prompt displays. The standard Windows prompt is set with:

```
PROMPT $P$G
```

Where:
- `$P` = current directory path
- `$G` = `>` symbol

This renders as: `C:\Users\username\>`

### Finding the Passphrase

The challenge hints pointed us toward Windows:
1. **Banner**: `[windows_10 | cmd.exe]` — explicitly mentions Windows cmd.exe
2. **Variable Name**: The challenge asks for a "key PROMPT" — the `PROMPT` environment variable
3. **Context**: Knowing Windows command prompt syntax

The passphrase is the literal string: **`$P$G`**

### Exploitation

```bash
[windows_10 | cmd.exe] Welcome good sire to our fine establishment.
Unfortunately, due to increased demand,
we have had to privatize our services.
Please enter the secret passphrase received from the environment to continue.
$P$G
Thank you for your patience. Here is your flag: nullctf{why_1s_it_r3srv3d_96e7ae4c34f711ea}
```

## Flag

```
nullctf{why_1s_it_r3srv3d_96e7ae4c34f711ea}
```

### Flag Analysis

The flag message "why_1s_it_r3srv3d" is a meta-hint. The `$P` and `$G` are **reserved escape sequences** in Windows — they have special, built-in meaning that cannot be changed. This is why they work as the passphrase; they're not obscure secrets but rather standard, well-known Windows conventions.

## Key Takeaways

- **Context clues matter**: The Windows-themed banner was crucial to solving this
- **Environment variables**: Knowing what standard environment variables contain is useful
- **System knowledge**: Understanding platform-specific features (like Windows prompt formatting) directly helps solve CTF challenges
- **Simplicity**: The solution wasn't hidden behind complex code—just requiring knowledge of a standard system feature
