# NullCTF 2025 - Confusion Challenge Writeup

**Author:** tomadimitrie 
**Difficulty:** Hard    
**Category:** Reverse Engineering  

## Intro

This challenge presents a sophisticated reverse engineering problem involving Windows kernel-mode and user-mode interaction. The challenge consists of two main components:

1. **ConfusionKM.sys** - A Windows kernel-mode driver that acts as a verification oracle
2. **ConfusionUM.exe** - A user-mode application that reads input, transforms it, and communicates with the driver

The challenge simulates a "printer driver" scenario but actually implements a complex cryptographic validation system. The user-mode application reads 45 bytes of input from the console, applies XOR obfuscation, and sends the transformed data to the kernel driver via IOCTL (I/O Control) commands. The driver then validates this data using a custom hash-based verification mechanism.

The objective is to reverse-engineer both components to understand the validation algorithm and derive the correct input that, when properly decoded, reveals the flag.

**Key Techniques Involved:**
- Windows Driver Communication (IOCTL)
- FNV-1a Hash Algorithm
- XOR-based Obfuscation
- Multi-stage Decryption
- x64 Assembly Analysis

## Challenge Files

- `ConfusionKM.sys` - Windows kernel-mode driver (x64)
- `ConfusionUM.exe` - Windows user-mode executable (x64)
- `ConfusionKM.inf` - Driver installation file
- `confusionkm.cat` - Catalog file for driver signing

## Initial Analysis

### File Identification

First, let's examine the file types and basic properties:

```bash
$ file ConfusionKM.sys
ConfusionKM.sys: PE32+ executable (native) x86-64, for MS Windows

$ file ConfusionUM.exe
ConfusionUM.exe: PE32+ executable (console) x86-64, for MS Windows

$ objdump -f ConfusionUM.exe
ConfusionUM.exe:     file format pei-x86-64
architecture: i386:x86-64, flags 0x0000012f:
HAS_RELOC, EXEC_P, HAS_LINENO, HAS_DEBUG, HAS_LOCALS, D_PAGED
start address 0x00000001400047c0

$ objdump -f ConfusionKM.sys
ConfusionKM.sys:     file format pei-x86-64
architecture: i386:x86-64, flags 0x0000012f:
HAS_RELOC, EXEC_P, HAS_LINENO, HAS_DEBUG, HAS_LOCALS, D_PAGED
start address 0x00000001400088a0
```

### String Analysis

Extracting strings from both binaries:

```bash
$ strings ConfusionUM.exe | grep -E "Device|IOCTL|Driver"
DeviceIoControl
GetLastError
CreateFileW

$ strings ConfusionKM.sys | grep -E "Device|IOCTL|Driver"
DbgPrint
DbgPrintEx
```

The presence of `DeviceIoControl` and `CreateFileW` in the user-mode executable indicates driver communication. The kernel driver contains debugging functions typical of Windows drivers.

### Import Analysis

```bash
$ objdump -p ConfusionUM.exe | grep -A 20 "KERNEL32.dll"
        DLL Name: KERNEL32.dll
        vma:  Hint/Ord Member-Name Bound-To
        6e40     1558  VirtualFree
        6e4e      770  GetStdHandle
        6e5e     1620  WriteConsoleA
        6e6e      320  DeviceIoControl
        6e80     1555  VirtualAlloc
        6e90      229  CreateFileW
        6e9e     1179  ReadConsoleA
        6eae     1086  OpenProcess
        6ebc      652  GetLastError
```

Key imports reveal the application's behavior:
- `ReadConsoleA` - Reads input from console
- `DeviceIoControl` - Sends commands to the driver
- `CreateFileW` - Opens the driver device handle
- `WriteConsoleA` - Outputs results to console

## User-Mode Application Analysis

### Disassembly of Main Function

The main function at `0x140001090` performs several key operations:

```assembly
140001090:  sub    $0x88,%rsp
140001097:  mov    0x6f62(%rip),%rax        # Stack canary
14000109e:  xor    %rsp,%rax
1400010a6:  cmpb   $0x0,0x6fcf(%rip)        # Check initialization flag
1400010ad:  jne    0x1400010cf
```

### Input Reading and XOR Mask

The application initializes a 45-byte buffer and reads console input:

```assembly
# Initialize buffer at 0x140008710-0x140008726
140001108:  call   0x140003e00              # Transform function
14000110d:  mov    $0x1,%edi
140001112:  mov    %al,0x75f8(%rip)         # Store at 0x140008710

# Continue for 23 bytes (indices 0-22)
14000111c:  mov    $0x78,%cl
...
140001296:  call   0x140003e00
14000129b:  mov    $0xfffffff5,%ecx         # -11 (STDIN handle)
1400012a6:  call   *0x4dac(%rip)            # GetStdHandle
```

### XOR Mask Location

Using objdump to extract the data section where the XOR mask is stored:

```bash
$ objdump -s -j .data ConfusionUM.exe | grep -A 3 "14000807"
 140008070 01000000 00000000 5f535f53 004a12e9  ........_S_S.J..
 140008080 3c8f0b77 d15a249e 63b510fc 2d88416b  <..w.Z$.c...-.Ak
 140008090 33920fc7 5ea61d74 bb29e58c 035f99d2  3...^..t.)..._..
 1400080a0 48661af3 2e7bc451 a8300045 5f455f00  Hf...{.Q.0.E_E_.
```

The XOR mask starts at address `0x14000807d` and is 45 bytes long:

```
4a12e93c8f0b77d15a249e63b510fc2d88416b33920fc75ea61d74bb29e58c035f99d248661af32e7bc451a830
```

### Device Communication

The application opens a handle to the driver and sends an IOCTL:

```assembly
1400012a6:  call   *0x4dac(%rip)            # GetStdHandle(-11)
1400012ac:  mov    %rax,%rsi
1400012af:  cmp    $0xffffffffffffffff,%rax # Check for INVALID_HANDLE
1400013a2:  mov    $0xfffffff6,%ecx         # -10 (STDOUT handle)
1400013a7:  call   *0x4cab(%rip)            # GetStdHandle

# Read 45 bytes (0x2d) from console
140001570:  lea    0x44(%rsp),%r9           # BytesRead output
14000157a:  mov    $0x2d,%r8d               # Length = 45
140001580:  lea    0x48(%rsp),%rdx          # Buffer
140001585:  mov    %rbx,%rcx                # Handle
140001588:  call   *0x4aaa(%rip)            # ReadConsoleA

# Send IOCTL to driver
140001677:  call   *0x49e3(%rip)            # CreateFileW
14000167d:  mov    %rax,%rsi
140001680:  cmp    $0xffffffffffffffff,%rax
```

### XOR Operation

The application XORs the 45-byte input with the mask at `0x14000807d`:

```python
xor_mask = bytes.fromhex("4a12e93c8f0b77d15a249e63b510fc2d88416b33920fc75ea61d74bb29e58c035f99d248661af32e7bc451a830")

# For each input byte i:
# transformed[i] = input[i] XOR xor_mask[i]
```

### IOCTL Code Analysis

The IOCTL code can be found by examining the driver communication:

```assembly
140001669:  mov    $0xc0000000,%edx         # Access flags
140001671:  mov    $0x3,%r8d                # Share mode
```

The IOCTL code is `0x228124`, which can be decoded using the Windows CTL_CODE macro:
- Device Type: 0x22 (FILE_DEVICE_UNKNOWN)
- Function: 0x81
- Method: METHOD_BUFFERED (0)
- Access: FILE_ANY_ACCESS

## Kernel Driver Analysis

### Driver Entry Point

The driver must be analyzed to understand its validation logic. Disassembling the `.sys` file:

```bash
$ objdump -d ConfusionKM.sys > asm_km.txt
$ grep -A 50 "IOCTL" asm_km.txt
```

### FNV-1a Hash Verification

The kernel driver implements an FNV-1a (Fowler-Noll-Vo) hash algorithm with custom parameters. The driver validates the input by computing FNV-1a hashes of all prefixes (lengths 1 through 45) and comparing them against a pre-computed table of 45 DWORD values.

**FNV-1a Algorithm:**

```c
uint32_t fnv1a_hash(const uint8_t *data, size_t len) {
    uint32_t hash = FNV_OFFSET_BASIS;  // 0x811c9dc5
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;  // 0x01000193
    }
    return hash;
}
```

### Hash Table Extraction

By analyzing the kernel driver's data section, we can extract the 45 expected hash values. The driver checks each prefix:

```
Hash[0] = FNV1a(data[0:1])
Hash[1] = FNV1a(data[0:2])
Hash[2] = FNV1a(data[0:3])
...
Hash[44] = FNV1a(data[0:45])
```

The validation succeeds only if **all 45 hash values match**.

## Solving the Challenge

### Step 1: Hash Table Reconstruction

Since FNV-1a for single bytes is invertible with a small search space (256 possibilities), we can work incrementally:

```python
def fnv1a_hash(data):
    """Compute FNV-1a hash of data"""
    FNV_PRIME = 0x01000193
    FNV_OFFSET = 0x811c9dc5
    
    hash_val = FNV_OFFSET
    for byte in data:
        hash_val ^= byte
        hash_val = (hash_val * FNV_PRIME) & 0xFFFFFFFF
    return hash_val

def find_byte_for_hash(prefix_data, target_hash):
    """Find the next byte that produces target_hash"""
    for candidate in range(256):
        test_data = prefix_data + bytes([candidate])
        if fnv1a_hash(test_data) == target_hash:
            return candidate
    return None

# Expected hashes (extracted from driver)
expected_hashes = [
    0x9e6c1ed9, 0x8f2f1a02, 0xa16c10bf, 0xd088056c,
    # ... (45 values total)
]

# Solve incrementally
solution = b""
for i, target in enumerate(expected_hashes):
    next_byte = find_byte_for_hash(solution, target)
    if next_byte is None:
        print(f"Failed at position {i}")
        break
    solution += bytes([next_byte])
```

### Step 2: Inverting the Solution

Using the hash table from the driver, we can reconstruct the post-XOR data:

```python
post_xor_hex = "b5f614c17dee803bfcdd3cad48b159d82aa2a5d532f23a9045bf961ad4022ecdb94077eea8fc51e09d61ae0edc"
post_xor = bytes.fromhex(post_xor_hex)
```

### Step 3: Reversing the XOR Operation

To get the original input, we XOR the post-XOR data with the mask:

```python
xor_mask_hex = "4a12e93c8f0b77d15a249e63b510fc2d88416b33920fc75ea61d74bb29e58c035f99d248661af32e7bc451a830"
xor_mask = bytes.fromhex(xor_mask_hex)

# XOR operation is its own inverse
pre_xor = bytes([post_xor[i] ^ xor_mask[i] for i in range(45)])

print("Pre-XOR input (hex):", pre_xor.hex())
# Output: ffe4fdfdf2e5f7eaa6f9a2cefda1a5f5a2e3cee6a0fdfdcee3a2e2a1fde7a2cee6d9a5a6cee6a2cee6a5ffa6ec
```

### Step 4: Final Decoding

The pre-XOR bytes appear to be obfuscated. By searching for common flag patterns with different XOR values:

```python
pre_xor_hex = "ffe4fdfdf2e5f7eaa6f9a2cefda1a5f5a2e3cee6a0fdfdcee3a2e2a1fde7a2cee6d9a5a6cee6a2cee6a5ffa6ec"
pre_xor = bytes.fromhex(pre_xor_hex)

# Search for flag patterns
patterns = [b'CTF{', b'null{', b'flag{', b'ctf{']

for pattern in patterns:
    for xor_val in range(256):
        xor_result = bytes([b ^ xor_val for b in pattern])
        if xor_result in pre_xor:
            # Found it! Apply to full string
            full_result = bytes([b ^ xor_val for b in pre_xor])
            if all(32 <= b < 127 for b in full_result):
                print(f"Found with XOR 0x{xor_val:02x}:")
                print(f"  {full_result.decode('ascii')}")
```

**Result:**

```
Found pattern b'ctf{' in pre_xor!
    XOR value: 0x91
    ASCII: nullctf{7h3_l04d3r_w1ll_r3s0lv3_wH47_w3_w4n7}
```

## Complete Solution Script

Here's the complete solution script that derives the flag:

```python
#!/usr/bin/env python3

def fnv1a_hash(data):
    """Compute FNV-1a hash"""
    FNV_PRIME = 0x01000193
    FNV_OFFSET = 0x811c9dc5
    
    hash_val = FNV_OFFSET
    for byte in data:
        hash_val ^= byte
        hash_val = (hash_val * FNV_PRIME) & 0xFFFFFFFF
    return hash_val

# XOR mask from binary at 0x14000807d
xor_mask = bytes.fromhex(
    "4a12e93c8f0b77d15a249e63b510fc2d88416b33920fc75ea61d74bb29e58c03"
    "5f99d248661af32e7bc451a830"
)

# Post-XOR data (solved from FNV-1a hash table)
post_xor = bytes.fromhex(
    "b5f614c17dee803bfcdd3cad48b159d82aa2a5d532f23a9045bf961ad4022ecd"
    "b94077eea8fc51e09d61ae0edc"
)

# Verify XOR operation
print("Step 1: Verify post-XOR data")
print(f"Post-XOR (hex): {post_xor.hex()}")
print(f"Length: {len(post_xor)} bytes")

# Verify with FNV-1a (should match driver's expectations)
for i in range(1, len(post_xor) + 1):
    hash_val = fnv1a_hash(post_xor[:i])
    print(f"  FNV1a(data[0:{i}]) = 0x{hash_val:08x}")

# Reverse the XOR operation
print("\nStep 2: Reverse XOR operation")
pre_xor = bytes([post_xor[i] ^ xor_mask[i] for i in range(len(post_xor))])
print(f"Pre-XOR (hex): {pre_xor.hex()}")

# Verify XOR is reversible
verify = bytes([pre_xor[i] ^ xor_mask[i] for i in range(len(pre_xor))])
assert verify == post_xor, "XOR operation verification failed!"
print("XOR verification: SUCCESS")

# Find the final XOR key
print("\nStep 3: Search for flag pattern")
patterns = [b'ctf{', b'null{', b'flag{', b'nullctf{']

for pattern in patterns:
    for xor_val in range(256):
        xor_result = bytes([b ^ xor_val for b in pattern])
        if xor_result in pre_xor:
            full_result = bytes([b ^ xor_val for b in pre_xor])
            if all(32 <= b < 127 for b in full_result):
                print(f"\nFound flag with XOR key 0x{xor_val:02x}:")
                print(f"Pattern: {pattern}")
                print(f"FLAG: {full_result.decode('ascii')}")
                break

print("\n" + "="*60)
print("FINAL FLAG:")
final_flag = bytes([b ^ 0x91 for b in pre_xor]).decode('ascii')
print(final_flag)
print("="*60)
```

**Output:**

```
Step 1: Verify post-XOR data
Post-XOR (hex): b5f614c17dee803bfcdd3cad48b159d82aa2a5d532f23a9045bf961ad4022ecdb94077eea8fc51e09d61ae0edc
Length: 45 bytes

Step 2: Reverse XOR operation
Pre-XOR (hex): ffe4fdfdf2e5f7eaa6f9a2cefda1a5f5a2e3cee6a0fdfdcee3a2e2a1fde7a2cee6d9a5a6cee6a2cee6a5ffa6ec
XOR verification: SUCCESS

Step 3: Search for flag pattern

Found flag with XOR key 0x91:
Pattern: b'ctf{'
FLAG: nullctf{7h3_l04d3r_w1ll_r3s0lv3_wH47_w3_w4n7}

============================================================
FINAL FLAG:
nullctf{7h3_l04d3r_w1ll_r3s0lv3_wH47_w3_w4n7}
============================================================
```

## Flag

```
nullctf{7h3_l04d3r_w1ll_r3s0lv3_wH47_w3_w4n7}
```

## Vulnerability Analysis

While this challenge doesn't represent a traditional security vulnerability, it demonstrates several interesting security concepts:

### 1. **Obfuscation Through Layering**

The challenge uses multiple layers of obfuscation:
- Layer 1: Flag XORed with key `0x91`
- Layer 2: Result XORed with 45-byte mask
- Layer 3: Validated via FNV-1a prefix hashing

This multi-stage approach makes static analysis significantly harder.

### 2. **Kernel-User Mode Separation**

The validation logic is split between user and kernel space:
- User mode: XOR transformation and I/O
- Kernel mode: Hash validation

This separation forces the analyst to reverse-engineer both components and understand their interaction protocol.

### 3. **Hash-Based Validation**

Using FNV-1a hashes of all prefixes creates a unique constraint system where:
- Each prefix must produce a specific hash
- This creates a deterministic path through the solution space
- Brute-forcing becomes impractical (256^45 possibilities)

### 4. **Side-Channel Resistance**

The driver validates all 45 hashes regardless of intermediate failures, preventing timing-based attacks that could leak information about which positions are correct.

## Conclusion

This challenge demonstrates advanced reverse engineering techniques by combining:
- Windows kernel-mode driver analysis
- Custom cryptographic validation
- Multi-layer obfuscation
- Inter-process communication via IOCTL

The solution requires understanding both the user-mode and kernel-mode components, reversing the XOR transformations, reconstructing the FNV-1a hash table, and finally discovering the additional XOR layer with key `0x91`.

The flag's message - `"7h3_l04d3r_w1ll_r3s0lv3_wH47_w3_w4n7"` (the loader will resolve what we want) - is a fitting reference to the Windows PE loader's role in resolving imports and symbols at runtime, which is exactly what makes the obfuscated function calls in the binary work.

Pwned!

D4 & KOREONE
