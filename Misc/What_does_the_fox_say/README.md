# NullCTF 2025 - What does the fox say? Challenge Writeup

**Author:** cshark3008  
**Difficulty:** Easy  
**Category:** Misc

## Challenge Description
> The fox left behind a strange melody... Hidden in the noise lies the truth. Can you figure out what the fox says? [🦊](https://www.youtube.com/watch?v=jofNR_WkoCE)
>
> Note: If you find strings that are not in the `nullctf{}` format, those are only parts. You need all of them combined to uravel the flag.
>
> [http://public.ctf.r0devnull.team:3012](http://public.ctf.r0devnull.team:3012/)

## Intro

"What does the fox say?" is a multi-stage challenge that combines web reconnaissance, steganography within web assets, and basic cryptography. The challenge requires players to investigate the provided website's resources thoroughly, identifying hidden data encoded within CSS animations and locating concealed files using standard enumeration techniques. The final solution involves combining the extracted information to decrypt a ciphertext.

## Initial Analysis

### Step 1: Initial Reconnaissance

Upon accessing the challenge URL, we are presented with a simple web page. A standard procedure in web challenges is to inspect the source code and loaded resources.

We fetch the main page and notice a reference to an external stylesheet:

```bash
curl -v http://public.ctf.r0devnull.team:3012
```

The response headers include a link to `style.css`:
```http
Link: <style.css>; rel=stylesheet;
```

### Step 2: Analyzing the CSS Animation

Inspecting `style.css` reveals a suspicious `@keyframes` animation named `blink`. This animation defines 127 steps, toggling the `opacity` property between `0` and `1`.

```css
@keyframes blink {
  0.00% { opacity: 1; }
  0.79% { opacity: 1; }
  0.79% { opacity: 1; }
  1.57% { opacity: 1; }
  /* ... many lines omitted ... */
  2.36% { opacity: 0; }
  /* ... */
}
```

The specific pattern of `1`s (visible) and `0`s (invisible) suggests a binary encoding or Morse code. Given the context of "melody" and "noise", Morse code is a strong candidate.

We can write a Python script to extract these values and decode them. We interpret:
*   Long sequences of `1`s (approx. 3-4 frames or more) as a **Dash (-)**.
*   Short sequences of `1`s as a **Dot (.)**.
*   Sequences of `0`s as spaces/separators.

#### Decoding Script

```python
import re
import itertools

# Load the CSS content
css = """... (content of style.css) ..."""

# Extract opacity values
pattern = r'opacity:\s*([01]);'
matches = re.findall(pattern, css)
binary_string = ''.join(matches)

# Group consecutive identical values
groups = [''.join(g) for k, g in itertools.groupby(binary_string)]

# Convert to Morse
morse = []
for group in groups:
    if '1' in group:
        if len(group) >= 4:
            morse.append('-')
        else:
            morse.append('.')
    else:
        if len(group) >= 4:
            morse.append(' ')
morse_str = ''.join(morse)
print(f"Extracted Morse: {morse_str}")

# Morse Code Dictionary
morse_code = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?'
}

morse_parts = morse_str.split(' ')
decoded = ""
for part in morse_parts:
    if part in morse_code:
        decoded += morse_code[part]

print(f"Decoded Message: {decoded}")
```

**Output:**
```
Extracted Morse: -.-- .-.. ...- .. ... ..--- ----- .---- ...--
Decoded Message: YLVIS2013
```

The decoded string `YLVIS2013` refers to the comedy duo Ylvis and their 2013 viral hit "The Fox (What Does the Fox Say?)". This confirms we are on the right track, but `null{YLVIS2013}` is not the flag. This string is likely a key or password.

### Step 3: Finding the Secret File

Continuing with web enumeration, we check `robots.txt`, a common place for CTF challenges to hide paths.

```bash
curl http://public.ctf.r0devnull.team:3012/robots.txt
```

**Output:**
```
User-agent: *
Disallow: /secret.txt
```

We fetch the disallowed file:

```bash
curl http://public.ctf.r0devnull.team:3012/secret.txt
```

**Content of `secret.txt`:**
```
The fox whispers a secret hidden in the noise... Can you hear it?
G44TUJJQIZLEU5DKHZTSONDNKRMF2YATGJ4D2VLPKUBDO5LFHNRFYVYCK5UCEMJU
```

### Step 4: Decrypting the Secret

We have a ciphertext: `G44TUJJQIZLEU5DKHZTSONDNKRMF2YATGJ4D2VLPKUBDO5LFHNRFYVYCK5UCEMJU`.
The character set (A-Z, 2-7) strongly suggests **Base32** encoding.

We also have the key `YLVIS2013` from the CSS analysis. A common technique in CTFs when you have a key and a binary blob is **XOR** encryption.

#### Decryption Script

```python
import base64
import itertools

encoded = "G44TUJJQIZLEU5DKHZTSONDNKRMF2YATGJ4D2VLPKUBDO5LFHNRFYVYCK5UCEMJU"
decoded_bytes = base64.b32decode(encoded)

keys = [
    "YLVIS2013",
    "ylvis2013",
]

def xor_decrypt(data, key):
    key_bytes = key.encode()
    decrypted = bytearray()
    for i, b in enumerate(data):
        decrypted.append(b ^ key_bytes[i % len(key_bytes)])
    return decrypted

print(f"Decoded bytes (hex): {decoded_bytes.hex()}")

for key in keys:
    try:
        decrypted = xor_decrypt(decoded_bytes, key)
        print(f"Key: {key}")
        print(f"  Hex: {decrypted.hex()}")
        try:
            print(f"  Str: {decrypted.decode('utf-8')}")
        except:
            print(f"  Str: (binary)")
            # Versuche, ob "null" oder "flag" drin vorkommt
            if b'null' in decrypted or b'flag' in decrypted:
                print("  FOUND FLAG MARKER!")
    except Exception as e:
        print(f"Error with key {key}: {e}")
```

**Execution Output:**
```
Decoded bytes (hex): 37393a253046564a746a3e6727346d54585d601332783d556f55023775653b625c57025768223134
Key: YLVIS2013
  Hex: 6e756c6c6374667b473372316e675f64696e395f64316e675f64316e393372316e673364316e677d
  Str: nullctf{G3r1ng_din9_d1ng_d1n93r1ng3d1ng}
Key: ylvis2013
  Hex: 4e554c4c4374667b471352114e475f64696e197f44114e675f64314e191352116e673364114e475d
  Str: NULLCtf{GRNG_dinDNg_d1NRng3dNG]
```

## Vulnerability Analysis

While this is a CTF challenge and not a real-world application vulnerability, it demonstrates concepts of **Security through Obscurity** and **Information Leakage**.

1.  **Data Hiding in CSS:** The challenge hides information (the key) within the operational parameters of the website's visual presentation (CSS Keyframes). This is a form of steganography. In a real-world scenario, developers might unintentionally leave comments or debug data in static assets.
2.  **Robots.txt Disclosure:** The `robots.txt` file is intended to instruct web crawlers, not to implement access control. Listing `/secret.txt` in `Disallow` explicitly tells an attacker that this file exists and is likely interesting. This is a common misconfiguration where sensitive paths are revealed in an attempt to hide them.

## Conclusion

The flag is `nullctf{G3r1ng_din9_d1ng_d1n93r1ng3d1ng}`, a phonetic representation of the sounds made by the fox in the Ylvis song.

Pwned!

KOREONE
