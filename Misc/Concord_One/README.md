# Concord One – CTF Writeup

## Challenge Information

| Field              | Value         |
| ------------------ | ------------- |
| **CTF**            | NullCTF       |
| **Category**       | Misc          |
| **Difficulty**     | Easy          |
| **Points**         | 413           |
| **Author**         | Stefan        |
| **Files provided** | None          |
| **Flag format**    | `nullctf{.*}` |

---

## Description

The *Concord One* challenge takes place entirely on Discord.
No files or external services are provided: interaction with the server and its features is the core of the challenge.

**Hint:**

> We do not provide assistance over voice channels.

This hint is essential and directly points toward the voice-related features of the server.

---

## TL;DR

The flag is hidden inside an **audio clip from the Discord soundboard** of a **temporary voice channel**.
After downloading the sound and listening carefully, the audio is identified as **Morse code**, which decodes to the flag.

**Technique:** Audio analysis / Morse code
**Concept:** Flag hidden in a Discord voice asset

---

## Solution Walkthrough

### Step 1 – Create a Temporary Voice Channel

Using the Discord bot provided by the challenge, create a **temporary voice channel**.
This step is required to access the server’s **soundboard**.

---

### Step 2 – Inspect the Soundboard

Once inside the voice channel, open the Discord **soundboard**.
Among the available sounds, one stands out:

```
f_l_a_g perchance
```

The name itself strongly suggests that this audio contains the flag.

---

### Step 3 – Download the Audio

Right-click on the sound and select:

```
Download sound
```

This saves the audio file locally for further analysis.

---

### Step 4 – Identify Morse Code

Listening to the audio reveals a clear pattern of short and long beeps with regular pauses — characteristic of **Morse code**.

For better inspection, the file can be opened with **Audacity**, which allows:

* Visualizing signal timing
* Slowing down playback
* Separating dots and dashes clearly

---

### Step 5 – Decode the Message

Decoding the Morse code (manually or with a decoder) yields:

```
MISTER_M0RSE
```

Formatted as a flag:

```
nullctf{MISTER_M0RSE}
```

---

## Flag

```
nullctf{MISTER_M0RSE}
```

---
pwned by **bosio**
