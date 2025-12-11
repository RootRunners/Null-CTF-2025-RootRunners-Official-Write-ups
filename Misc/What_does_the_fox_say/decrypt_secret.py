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
