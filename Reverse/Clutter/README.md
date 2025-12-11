# NullCTF 2025 - Clutter Challenge Writeup

**Author:** cshark3008  
**Category:** Reverse Engineering  
**Difficulty:** Medium  

**Challenge Description**:

> A Flutter app hides its “premium unlock key” using secure storage, obfuscation, and a native channels that decrypts a flag. Reverse the app and recover the real flag. No guessing.

## Intro

The challenge provides an Android APK (`app-release.apk`). The goal is to reverse engineer the application to find the hidden flag. The description hints at a "premium unlock key", native channels, and decryption.

## Initial Analysis

We start by examining the APK file. Since it's an Android app, we use `apktool` to decompile it and inspect the resources and Smali code.

```bash
apktool d app-release.apk -o clutter_decompiled
```

Listing the libraries in `lib/` confirms it is a Flutter application (`libflutter.so`), but it also contains a custom native library `libapp.so` (standard for Flutter) and `libdatastore_shared_counter.so`.

However, the core logic for Flutter apps often resides in the Dart snapshot (in `libapp.so`) which is hard to reverse, or in the platform-specific code (Java/Kotlin) that interacts with Flutter via Platform Channels.

We check `AndroidManifest.xml` to find the main activity:
```xml
<activity android:name="com.example.clutter.MainActivity" ... >
```

## Static Analysis: Java/Smali

We navigate to `smali/com/example/clutter/MainActivity.smali`.

### MainActivity.smali

The `MainActivity` extends `FlutterActivity` and sets up a `MethodChannel`.

```smali
# instance fields
.field public final c:Ljava/lang/String;

# direct methods
.method public constructor <init>()V
    ...
    const-string v0, "com.ctf.app/premium"
    iput-object v0, p0, Lcom/example/clutter/MainActivity;->c:Ljava/lang/String;
    ...
```

In `configureFlutterEngine`, it initializes the channel and sets a handler:

```smali
.method public final configureFlutterEngine(Lio/flutter/embedding/engine/FlutterEngine;)V
    ...
    new-instance v0, Lio/flutter/plugin/common/MethodChannel;
    ...
    iget-object v1, p0, Lcom/example/clutter/MainActivity;->c:Ljava/lang/String; # "com.ctf.app/premium"
    invoke-direct {v0, p1, v1}, Lio/flutter/plugin/common/MethodChannel;-><init>(...);
    
    new-instance p1, LB/c;
    invoke-direct {p1, p0}, LB/c;-><init>(Lcom/example/clutter/MainActivity;)V
    
    invoke-virtual {v0, p1}, Lio/flutter/plugin/common/MethodChannel;->setMethodCallHandler(...)V
    ...
```

The handler is implemented in `LB/c;`.

### B/c.smali (The Handler)

We examine `smali/B/c.smali` and look for the `onMethodCall` method. This method handles incoming messages from the Flutter side.

```smali
.method public onMethodCall(Lio/flutter/plugin/common/MethodCall;Lio/flutter/plugin/common/MethodChannel$Result;)V
    ...
    iget-object v0, p1, Lio/flutter/plugin/common/MethodCall;->method:Ljava/lang/String;
    const-string v1, "unlockPremium"
    invoke-static {v0, v1}, LU0/h;->a(Ljava/lang/Object;Ljava/lang/Object;)Z
    ...
    if-eqz v0, :cond_5
    
    const-string v0, "key_hex"
    invoke-virtual {p1, v0}, Lio/flutter/plugin/common/MethodCall;->argument(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object p1
    check-cast p1, Ljava/lang/String;
    ...
```

The handler expects a method named `unlockPremium` with an argument `key_hex`.

It then performs the following operations:
1.  **Hex Decode**: Calls `MainActivity.a(String)` to convert the hex string to a byte array.
2.  **Prefix Check**: Converts the bytes to a String and checks if it starts with "INTERNAL".
    ```smali
    new-instance v0, Ljava/lang/String;
    ...
    const-string v3, "INTERNAL"
    invoke-virtual {v0, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z
    ```
3.  **Decryption**: If the check passes, it uses the byte array as an AES key to decrypt a hardcoded hex string.
    ```smali
    const-string v0, "768f085e7361835b5b3cdfdfcec27cfb0e8ce352b4b1cae7c039e3e564a52016973dcba39daff68d2e56b9bde0acad78"
    invoke-static {v0}, Lcom/example/clutter/MainActivity;->a(Ljava/lang/String;)[B
    move-result-object v0
    invoke-virtual {p1, v0}, Ljavax/crypto/Cipher;->doFinal([B)[B
    ```
4.  **Flag Check**: It checks if the decrypted result starts with `nullctf{`.

## Dynamic Analysis: Intercepting the Key

We know the native code expects a key starting with "INTERNAL". We want to know what the Flutter app is actually sending. Since the Flutter code is compiled into `libapp.so`, reversing it statically is difficult. Instead, we can patch the Smali code to log the incoming `key_hex` before the check fails.

### Patching the APK

We modify `smali/B/c.smali` to insert a logging call.

**Original Code:**
```smali
    :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I
```

**Patched Code:**
```smali
    :cond_0
    const-string v2, "MY_DEBUG"
    invoke-static {v2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    invoke-virtual {p1}, Ljava/lang/String;->length()I
```

We then rebuild and sign the APK:
1.  `apktool b clutter_decompiled --use-aapt2 -o app-patched.apk`
2.  `zipalign -f -v 4 app-patched.apk app-patched-aligned.apk`
3.  `apksigner sign --ks debug.keystore ... app-patched-aligned.apk`

### Running the Patched App

We install the patched APK on an emulator and monitor `logcat`.

```bash
adb install app-patched-aligned-signed.apk
adb logcat -c
adb shell am start -n com.example.clutter/.MainActivity
```

After interacting with the app (entering a dummy PIN), we see the following log:

```
D/MY_DEBUG( 2760): e054e974861e03089b59fc67e3661112
```

## Key Recovery

The logged hex string is `e054e974861e03089b59fc67e3661112`.
This does **not** start with "INTERNAL" (which is `494e5445524e414c` in hex).

However, the app is sending this specific value. It is likely obfuscated. A common obfuscation technique is XOR. We know the plaintext *must* start with "INTERNAL".

We can perform a Known Plaintext Attack (KPA) to find the XOR mask.

**Plaintext (Prefix):** `INTERNAL` -> `49 4e 54 45 52 4e 41 4c`  
**Ciphertext (Prefix):** `e0 54 e9 74 86 1e 03 08`

**Calculating the Mask:**
```python
>>> p = b"INTERNAL"
>>> c = bytes.fromhex("e054e974861e0308")
>>> mask = bytes([a ^ b for a, b in zip(p, c)])
>>> print(mask.hex())
a91abd31d4504244
```

The mask is `a91abd31d4504244`. Assuming this mask repeats for the rest of the string (8 bytes), we can decrypt the suffix.

**Ciphertext (Suffix):** `9b 59 fc 67 e3 66 11 12`

**Decrypting Suffix:**
```python
>>> c_suffix = bytes.fromhex("9b59fc67e3661112")
>>> mask = bytes.fromhex("a91abd31d4504244")
>>> suffix = bytes([a ^ b for a, b in zip(c_suffix, mask)])
>>> print(suffix)
b'2CAV76SV'
```

The full key is `INTERNAL` + `2CAV76SV` = `INTERNAL2CAV76SV`.

## Decrypting the Flag

Now we have the AES key and the ciphertext (from `B/c.smali`). We can write a script to decrypt the flag.

**Ciphertext:** `768f085e7361835b5b3cdfdfcec27cfb0e8ce352b4b1cae7c039e3e564a52016973dcba39daff68d2e56b9bde0acad78`
**Key:** `INTERNAL2CAV76SV`
**Algorithm:** AES-ECB (inferred from `Cipher.getInstance("AES/ECB/PKCS5Padding")` in Smali).

### Solution Script

```python
from Crypto.Cipher import AES
import binascii

# Hardcoded ciphertext from Smali
ciphertext_hex = "768f085e7361835b5b3cdfdfcec27cfb0e8ce352b4b1cae7c039e3e564a52016973dcba39daff68d2e56b9bde0acad78"
ciphertext = binascii.unhexlify(ciphertext_hex)

# Recovered Key
key = b"INTERNAL2CAV76SV"

# Decrypt
cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(ciphertext)

# Remove padding (PKCS7/PKCS5)
pad_len = decrypted[-1]
flag = decrypted[:-pad_len]

print(f"Flag: {flag.decode('utf-8')}")
```

**Output:**
```
Flag: nullctf{pr3m1um_c0d3_15_ju5t_flutt3r_m4g1c}
```

## Summary

The application's security relied on:
1.  **Obfuscation**: Sending an XORed key from Flutter to Native code.
2.  **Native Checks**: Validating the key structure ("INTERNAL" prefix) in native code.
3.  **Hardcoded Ciphertext**: Storing the encrypted flag directly in the code.

The vulnerability was the leakage of the key structure via the native check (`startsWith("INTERNAL")`) and the ability to intercept the obfuscated key via dynamic analysis (logging). This allowed for a trivial XOR mask recovery and subsequent decryption of the hardcoded flag.

Pwned!

KOREONE
