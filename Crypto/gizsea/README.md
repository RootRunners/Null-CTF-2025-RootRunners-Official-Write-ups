# Gizsea – Crypto Writeup

## Challenge Description

The challenge exposes a custom encryption algorithm called **Gizsea**, accessible
through a remote service. The server offers three options:

1. Encrypt arbitrary plaintext  
2. Decrypt arbitrary ciphertext (with restrictions)  
3. Print the encrypted flag  

The author claims the cipher is “indestructible”, but its construction
allows the attacker to build a full encryption oracle and decrypt the flag.

---

## Cipher Structure

The cipher works on **16-byte blocks** and internally uses AES with a **non-standard mode**.

The decryption logic follows this rule:

P_i = E_k(C_i ⊕ P_{i-1}), P_0 = IV


This is **not a secure block mode** and leaks critical structure when an oracle is available.

---

## Vulnerability

The server allows:
- Encrypting chosen plaintext
- Decrypting chosen ciphertext (except blocks matching the flag ciphertext)

This combination enables construction of an **AES encryption oracle `E_k(x)`**,
even though AES itself is not directly exposed.

---

## Step 1 – Recover `D_k(0)`

Encrypt **two blocks of zeroes**:

Encrypt(00...00 || 00...00)

The second ciphertext block equals:

D_k(0)

From the server:

Dk(0) = 562f66b7b815e1045a83bd34c616c09c


---

## Step 2 – Recover the IV

Encrypt **one block of zeroes**:

C = D_k(0) ⊕ IV

Thus:

IV = C ⊕ D_k(0)

From the server:
iv = 179b672c81746def671da5e56a802286

---

## Step 3 – Obtain Encrypted Flag

Using option `3`, the server returns the encrypted flag:

flag_enc (3 blocks)


---

## Step 4 – Build `E_k(x)` Oracle

To compute `E_k(X)`:

1. Choose:
C1 = D_k(0) ⊕ IV
2. Send:
Decrypt(C1 || X)
Because the first plaintext block becomes zero, the second block equals: P2 = E_k(X)

This provides a full **AES encryption oracle**.

---

## Step 5 – Decrypt the Flag

Using the decryption rule:

P_i = E_k(C_i ⊕ P_{i-1})


Procedure:
- `P₀ = IV`
- `Z_i = C_i ⊕ P_{i-1}`
- `P_i = E_k(Z_i)`

Applying this block-by-block decrypts the entire flag.

---

## Flag

nullctf{z1g_z4g_cr7pt0_fl1p_fl0p}
