# NullCTF 2025 - Big Lez Challenge Writeup

**Author:** xrp  
**Difficulty:** hard  
**Category:** Reverse Engineering  
**Challenge Description:** Ya fucken' druggo

## Intro

The "Big Lez" challenge is a reverse engineering challenge that presents participants with a Windows PE executable (`bigLez.exe`) along with its decompiled C source code (`bigLez.exe.c`) and an encrypted flag file (`flag.enc`). The challenge requires understanding a complex encryption scheme that involves multiple layers of obfuscation, dynamic key generation based on runtime calculations, and Windows CryptoAPI for AES encryption.

The core complexity lies in the multi-stage key derivation process:
1. String manipulation and selective word extraction from obfuscated text
2. Dynamic calculation of a rolling XOR key based on the executable's own machine code
3. SHA-256 hashing for final key derivation
4. Custom IV generation through XOR operations

## Initial Analysis

### Step 1: Understanding the Program Flow

Let's start by examining the main function in `bigLez.exe.c`:

```c
int __cdecl _main(int _Argc,char **_Argv,char **_Env)
{
  ___main();
  intro();
  process_magic();
  return 0;
}
```

The program executes two primary functions:
1. `intro()` - Displays text and calculates a dynamic value
2. `process_magic()` - Handles the encryption logic

### Step 2: Analyzing the `process_magic()` Function

The `process_magic()` function is the heart of the encryption scheme. Let's examine its key components:

```c
void __cdecl process_magic(void)
{
  // ... variable declarations ...
  
  build_stack_strings(local_2b8,local_31c,local_380);
  strcpy(local_580,local_2b8);
  strcat(local_580,local_31c);
  strcat(local_580,local_380);
  local_18 = strlen(local_580);
  
  // Generate IV by XORing with string length
  for (local_10 = 0; local_10 < 0x10; local_10 = local_10 + 1) {
    local_590[local_10] = (&DAT_00406000)[local_10] ^ (byte)local_18;
  }
  
  // Extract specific words from strings
  append_word_at_index(local_154,local_2b8,0);
  append_word_at_index(local_154,local_2b8,5);
  append_word_at_index(local_154,local_2b8,7);
  append_word_at_index(local_154,local_31c,1);
  append_word_at_index(local_154,local_31c,3);
  append_word_at_index(local_154,local_380,2);
```

The function performs several operations:
1. Builds three strings on the stack
2. Concatenates them to calculate their total length
3. Uses this length to generate an IV by XORing with `DAT_00406000`
4. Extracts specific words from the strings to build a passphrase

### Step 3: Understanding `build_stack_strings()`

This function constructs three hardcoded strings:

```c
void __cdecl build_stack_strings(undefined1 *param_1,undefined1 *param_2,undefined1 *param_3)
{
  *param_1 = 0x68;  // 'h'
  param_1[1] = 0x65;  // 'e'
  param_1[2] = 0x68;  // 'h'
  param_1[3] = 0x65;  // 'e'
  param_1[4] = 0x2c;  // ','
  // ... continues ...
```

Converting these hex values reveals:
- String 1: `"hehe, aren't we all chasing the light mate?"`
- String 2: `" Lookin' everywhere to find it,"`
- String 3: `" everywhere but within."`

### Step 4: Word Extraction Logic

The `append_word_at_index()` function tokenizes strings and extracts specific words:

```c
void __cdecl append_word_at_index(undefined4 param_1,undefined4 param_2,int param_3)
{
  undefined1 local_114 [256];
  int local_14;
  int local_10;
  
  strcpy(local_114,param_2);
  local_10 = strtok(local_114," ,.?!\'");
  local_14 = 0;
  while( true ) {
    if (local_10 == 0) {
      return;
    }
    if (local_14 == param_3) break;
    local_10 = strtok(0," ,.?!\'");
    local_14 = local_14 + 1;
  }
  strcat(param_1,local_10);
  return;
}
```

The function uses `strtok()` with delimiters `" ,.?!\'"` to split strings into words.

Based on the calls:
- `append_word_at_index(local_154,local_2b8,0)` → "hehe" (index 0)
- `append_word_at_index(local_154,local_2b8,5)` → "chasing" (index 5)
- `append_word_at_index(local_154,local_2b8,7)` → "light" (index 7)
- `append_word_at_index(local_154,local_31c,1)` → "everywhere" (index 1)
- `append_word_at_index(local_154,local_31c,3)` → "find" (index 3)
- `append_word_at_index(local_154,local_380,2)` → "within" (index 2)

This creates the string: `"hehechasinglighteverywherefindwithin"`

### Step 5: The `_jointStep` Dynamic Key

The `intro()` function calculates a dynamic value called `_jointStep`:

```c
void __cdecl intro(void)
{
  // ... display code omitted ...
  
  build_stack_strings(local_84,local_e8,local_14c);
  _jointStep = 0x55aa55aa;
  
  // ... animation code omitted ...
  
  for (local_1c = 0; local_1c < 100; local_1c = local_1c + 1) {
    _jointStep = (uint)(byte)intro[local_1c] ^ _jointStep << 5 ^ _jointStep >> 3;
  }
  return;
}
```

Critical observation: `intro[local_1c]` references the function's own machine code! The variable `intro` is declared as `undefined intro;` at address `0x00401000` (based on the symbol table), which actually points to the function itself.

The algorithm iterates over the first 100 bytes of the `intro()` function's machine code and performs:
```
_jointStep = byte ^ (_jointStep << 5) ^ (_jointStep >> 3)
```

This creates a value dependent on the actual binary code of the executable.

### Step 6: XOR with `_jointStep`

Back in `process_magic()`, the passphrase is XORed with `_jointStep`:

```c
local_1c = &_jointStep;
local_14 = 0;
while (uVar1 = strlen(local_154), local_14 < uVar1) {
  local_154[local_14] = local_154[local_14] ^ *(byte *)((int)local_1c + (local_14 & 3));
  local_14 = local_14 + 1;
}
```

The XOR operation uses `_jointStep` as a 4-byte repeating key (note `local_14 & 3` which gives indices 0-3).

### Step 7: Key Derivation via SHA-256

The XORed string is then hashed:

```c
BVar2 = _CryptCreateHash_20(local_28,0x800c,0,0,&local_2c);
if (BVar2 != 0) {
  dwDataLen = strlen(local_154);
  _CryptHashData_16(local_2c,local_154,dwDataLen,0);
  BVar2 = _CryptGetHashParam_20(local_2c,2,(BYTE *)&local_50,&local_54,0);
```

The constant `0x800c` corresponds to `CALG_SHA_256` in Windows CryptoAPI, producing a 32-byte key suitable for AES-256.

### Step 8: AES Encryption

Finally, the flag is encrypted using AES:

```c
local_5c0[0] = '\b';  // PLAINTEXTKEYBLOB structure
local_5c0[1] = 2;
local_5c0[2] = '\0';
local_5c0[3] = '\0';
local_5c0[4] = '\x10';  // 0x10 = 16 bytes key size indicator
local_5c0[5] = 'f';     // 0x66 0x00 = CALG_AES_256
local_5c0[6] = '\0';
local_5c0[7] = '\0';
local_5c0[8] = ' ';     // 0x20 = 32 bytes key length
// ... key data copied here ...

BVar2 = _CryptImportKey_24(local_28,local_5c0,0x2c,0,0,&local_30);
if (BVar2 != 0) {
  _CryptSetKeyParam_16(local_30,1,local_590,0);  // Set IV (KP_IV = 1)
  local_20 = 0x100;
  BVar2 = _CryptEncrypt_28(local_30,0,1,0,local_254,&local_594,0x100);
```

The encryption uses:
- **Algorithm:** AES-256-CBC
- **Key:** 32-byte SHA-256 hash of XORed passphrase
- **IV:** 16-byte array from `DAT_00406000` XORed with string length

## Extracting Binary Data

The decompiled C code references two data structures we need:
1. `DAT_00406000` - The base IV data
2. `intro` function machine code - For calculating `_jointStep`

### Locating the Data in the Binary

First, examine the binary structure:

```bash
$ objdump -h bigLez.exe

bigLez.exe:     Dateiformat pei-i386

Sektionen:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00003744  00401000  00401000  00000400  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE, DATA
  1 .data         0000001c  00405000  00405000  00003c00  2**2
                  CONTENTS, ALLOC, LOAD, DATA
  2 .sassy        00000010  00406000  00406000  00003e00  2**2
                  CONTENTS, ALLOC, LOAD, DATA
```

The section `.sassy` at VMA `0x00406000` corresponds to our `DAT_00406000`! File offset is `0x3e00`.

Find the `intro` function location:

```bash
$ objdump -t bigLez.exe | grep intro
[ 34](sec  1)(fl 0x00)(ty   20)(scl   2) (nx 0) 0x000007e1 _intro
```

The `intro` function is at offset `0x7e1` from the `.text` section start. Since `.text` starts at file offset `0x400`:
```
File offset = 0x400 + 0x7e1 = 0xbe1
```

### Extracting the Bytes

```bash
$ xxd -s 0x3e00 -l 16 bigLez.exe
00003e00: 1600 0518 0015 000d 0a08 0f00 0304 0415  ................

$ xxd -s 0xbe1 -l 100 bigLez.exe
00000be1: 5589 e581 ec58 0100 008d 85b8 feff ff89  U....X..........
00000bf1: 4424 088d 851c ffff ff89 4424 048d 4580  D$........D$..E.
00000c01: 8904 24e8 57fc ffff c705 2090 4000 aa55  ..$.W..... .@..U
00000c11: aa55 c745 f400 0000 00eb 298d 5580 8b45  .U.E......).U..E
00000c21: f401 d00f b600 0fbe c089 0424 e856 2d00  ...........$.V-.
00000c31: 00c7 0424 2800 0000 e84a 2e00 0083 ec04  ...$(....J......
00000c41: 8345 f401                                .E..
```

We now have:
- **DAT_00406000:** `1600 0518 0015 000d 0a08 0f00 0304 0415`
- **intro bytes:** 100 bytes starting from `5589e581...`

## Building the Decryption Solution

Now we can implement the decryption in Python:

```python
import hashlib
from Crypto.Cipher import AES
import struct

# Data
dat_406000 = bytes.fromhex("160005180015000d0a080f0003040415")
intro_bytes = bytes.fromhex(
    "5589e581ec580100008d85b8feffff89"
    "4424088d851cffffff894424048d4580"
    "890424e857fcffffc70520904000aa55"
    "aa55c745f400000000eb298d55808b45"
    "f401d00fb6000fbec0890424e8562d00"
    "00c7042428000000e84a2e000083ec04"
    "8345f401"
)

# Calculate _jointStep
joint_step = 0x55aa55aa
for b in intro_bytes:
    # _jointStep = (uint)(byte)intro[local_1c] ^ _jointStep << 5 ^ _jointStep >> 3;
    # Python handles large integers, so we need to mask to 32-bit
    val = (b ^ (joint_step << 5) ^ (joint_step >> 3)) & 0xFFFFFFFF
    joint_step = val

print(f"Final joint_step: {hex(joint_step)}")

# Construct local_154
# Strings
s1 = "hehe, aren't we all chasing the light mate?"
s2 = " Lookin' everywhere to find it,"
s3 = " everywhere but within."

def get_tokens(s):
    delimiters = " ,.?!\'"
    tokens = []
    current_token = ""
    for char in s:
        if char in delimiters:
            if current_token:
                tokens.append(current_token)
                current_token = ""
        else:
            current_token += char
    if current_token:
        tokens.append(current_token)
    return tokens

tokens1 = get_tokens(s1)
tokens2 = get_tokens(s2)
tokens3 = get_tokens(s3)

print(f"Tokens1: {tokens1}")
print(f"Tokens2: {tokens2}")
print(f"Tokens3: {tokens3}")

words = [
    tokens1[0], # hehe
    tokens1[5], # chasing
    tokens1[7], # light
    tokens2[1], # everywhere
    tokens2[3], # find
    tokens3[2]  # within
]

local_154_str = "".join(words)
print(f"local_154 string: {local_154_str}")

local_154 = bytearray(local_154_str.encode('ascii'))

# XOR local_154 with joint_step
joint_step_bytes = struct.pack('<I', joint_step) # Little endian
for i in range(len(local_154)):
    local_154[i] ^= joint_step_bytes[i % 4]

print(f"local_154 XORed: {local_154.hex()}")

# Hash to get Key
key = hashlib.sha256(local_154).digest()
print(f"Key: {key.hex()}")

# Calculate IV
# local_18 = strlen(local_580)
# s1 + s2 + s3 length
len_s1 = len(s1)
len_s2 = len(s2)
len_s3 = len(s3)
local_18 = len_s1 + len_s2 + len_s3
print(f"local_18: {local_18}")

iv = bytearray()
for i in range(16):
    iv.append(dat_406000[i] ^ local_18)

print(f"IV: {iv.hex()}")

# Decrypt
try:
    with open("flag.enc", "rb") as f:
        ciphertext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    print(f"Plaintext: {plaintext}")
    
    # Remove padding if necessary (PKCS7 is standard)
    # But let's just print it first
except Exception as e:
    print(f"Error: {e}")
```

## Running the Solution

```bash
$ python3 solve.py
Final joint_step: 0xd0eb7eac
Tokens1: ['hehe', 'aren', 't', 'we', 'all', 'chasing', 'the', 'light', 'mate']
Tokens2: ['Lookin', 'everywhere', 'to', 'find', 'it']
Tokens3: ['everywhere', 'but', 'within']
local_154 string: hehechasinglighteverywherefindwithin
local_154 XORed: c41b83b5cf168aa3c5108cbcc51983a4c9088ea2d50983b5de1b8db9c21a9cb9d81682be
Key: 4213124efd426aaef1a71375f19a1143b5ddcf38f8c9897f0b08f65ad0d7f0d4
local_18: 97
IV: 776164796174616c6b696e6162656574
Plaintext: b'NULLCTF{7H1S_1S_A_N1C3_PL4C3_M8}\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
```

## Flag

```
NULLCTF{7H1S_1S_A_N1C3_PL4C3_M8}
```

## Conclusion

The "Big Lez" challenge demonstrates an interesting approach to obfuscating encryption keys by deriving them from the executable's own code. The challenge requires careful analysis of both the decompiled source code and the raw binary to extract all necessary components for decryption. The combination of string manipulation, self-referential code, and proper cryptographic primitives creates a multi-layered puzzle that tests various reverse engineering skills.

The solution path involves:
1. Understanding the encryption algorithm from decompiled code
2. Identifying data dependencies that exist only in the binary
3. Extracting raw bytes from specific sections of the PE file
4. Reimplementing the key derivation algorithm
5. Decrypting the flag using standard cryptographic libraries

This challenge exemplifies how understanding both high-level program logic and low-level binary representation is essential for comprehensive reverse engineering.

Pwned!

KOREONE
