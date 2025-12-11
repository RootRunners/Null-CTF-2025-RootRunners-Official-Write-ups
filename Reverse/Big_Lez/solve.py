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
