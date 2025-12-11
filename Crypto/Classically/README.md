# NullCTF 2025 - Classically Challenge Writeup

**Challenge:** Classically  
**Category:** Cryptography  
**Difficulty:** Easy  
**Author:** infernosalex  
**Description:** "Do you think you can solve this classically?"

## Intro

This challenge presents a classical linear algebra problem in the context of cryptography. The flag is encrypted using matrix-vector multiplication over a finite field (modulo a prime). Participants are given a 64×64 matrix `M`, the modulus `mod = 0x10001` (65537, a prime number), and the encrypted result vector. The goal is to recover the original flag by solving a system of linear equations modulo the prime.

The challenge demonstrates that even though matrix multiplication provides a mathematical transformation, if the matrix is invertible and both the matrix and result are known, the original message can be recovered through matrix inversion - a "classical" approach to solving linear systems.

## Initial Analysis

The challenge provides two files:

### 1. `main.py` - Encryption Implementation

```python
from M import M

flag = open("./flag.txt", "r").read().encode()

n = 64
assert len(flag) == n and flag[:4] == b"ctf{" and flag[-1:] == b"}"
mod = 0x10001

result = []

assert len(M) == n
for v in M:
	assert len(v) == n

for i in range(n):
	dot = 0
	for j in range(n):
		dot += M[i][j] * flag[j]
	result.append(dot % mod)

print(result)
# [29839, 662, 50523, 15906, 32667, 25159, 5172, 11685, 5618, 62174, 54405, 34902, 12259, 59526, 12299, 37286, 6055, 16813, 42488, 40708, 7662, 24263, 24047, 55429, 64420, 18167, 36330, 18325, 61471, 559, 32085, 23807, 26543, 26886, 24249, 45980, 23360, 15196, 42894, 33054, 22073, 23786, 63308, 44883, 60088, 38633, 54798, 42893, 29049, 25567, 33563, 49913, 63714, 51666, 60112, 19656, 13133, 11756, 34277, 55622, 14539, 54580, 48536, 1337]
```

**Key Points:**
- The flag has exactly 64 bytes
- Flag format is `ctf{...}`
- Encryption uses a 64×64 matrix multiplication
- The modulus is `0x10001` (65537), which is a Fermat prime
- Each byte of the flag is treated as an integer
- The result is a vector of 64 integers, each representing a dot product modulo 65537

### 2. `M.py` - The Transformation Matrix

This file contains the 64×64 matrix `M` with seemingly random integer values modulo 65537. The matrix appears to be randomly generated but is carefully chosen to be invertible modulo the prime.

```python
M = [
    [57121, 19227, 32536, 277, 59722, ...],  # Row 0
    [53887, 13460, 11431, 22534, 36534, ...], # Row 1
    # ... 62 more rows
]
```

The matrix elements range from 0 to 65536, representing values in the finite field ℤ/65537ℤ.

### 3. Output Result Vector

```python
result = [29839, 662, 50523, 15906, 32667, 25159, 5172, 11685, 5618, 62174, 
          54405, 34902, 12259, 59526, 12299, 37286, 6055, 16813, 42488, 40708, 
          7662, 24263, 24047, 55429, 64420, 18167, 36330, 18325, 61471, 559, 
          32085, 23807, 26543, 26886, 24249, 45980, 23360, 15196, 42894, 33054, 
          22073, 23786, 63308, 44883, 60088, 38633, 54798, 42893, 29049, 25567, 
          33563, 49913, 63714, 51666, 60112, 19656, 13133, 11756, 34277, 55622, 
          14539, 54580, 48536, 1337]
```

This is the encrypted flag represented as 64 integers.

## Mathematical Background

### The Encryption Scheme

The encryption can be represented mathematically as:

**Equation:** `M × flag = result (mod 65537)`

Where:
- `M` is a 64×64 matrix
- `flag` is a 64×1 column vector (the flag bytes)
- `result` is a 64×1 column vector (the encrypted output)
- All operations are performed modulo 65537

In expanded form, for each row `i`:
```
result[i] = (M[i][0] × flag[0] + M[i][1] × flag[1] + ... + M[i][63] × flag[63]) mod 65537
```

### Why This is Vulnerable

This encryption scheme has a critical vulnerability: **it's a linear transformation with a known, invertible matrix.**

1. **Linearity:** The encryption is a linear operation, meaning the relationship between plaintext and ciphertext is deterministic and algebraic.

2. **Known Matrix:** The transformation matrix `M` is provided to us, eliminating any security through obscurity.

3. **Invertible Matrix:** For the encryption to work uniquely (one-to-one mapping), the matrix must be invertible modulo 65537. This is a requirement for any practical use but also enables decryption.

4. **No Additional Security:** Unlike modern encryption schemes that use:
   - Multiple rounds of transformations
   - Non-linear operations (S-boxes)
   - Key-dependent transformations
   - Diffusion and confusion principles
   
   This scheme uses only a single linear transformation.

### The Decryption Process

To recover the flag, we need to solve:
```
flag = M⁻¹ × result (mod 65537)
```

Where `M⁻¹` is the modular inverse of matrix `M` modulo 65537.

**Requirements for Matrix Inversion mod p:**
- The modulus must be prime (65537 is prime)
- The matrix determinant must be non-zero modulo the prime
- The determinant must be coprime with the modulus

Since 65537 is a Fermat prime (2^16 + 1), it has nice properties for modular arithmetic, making the inversion computationally efficient.

## Solution Approach

### Step 1: Understanding the Problem

We need to:
1. Import the matrix `M` and result vector
2. Compute the modular inverse of matrix `M` modulo 65537
3. Multiply the inverse matrix with the result vector
4. Convert the resulting integers back to ASCII characters

### Step 2: Implementation Strategy

We'll use the `sympy` library, which provides:
- `Matrix` class for matrix operations
- `inv_mod(p)` method for computing modular inverses
- Automatic handling of modular arithmetic

### Step 3: Complete Solution Code

Here's the complete solution script (`solve.py`):

```python
from M import M
from sympy import Matrix

mod = 0x10001
result = [29839, 662, 50523, 15906, 32667, 25159, 5172, 11685, 5618, 62174, 54405, 34902, 12259, 59526, 12299, 37286, 6055, 16813, 42488, 40708, 7662, 24263, 24047, 55429, 64420, 18167, 36330, 18325, 61471, 559, 32085, 23807, 26543, 26886, 24249, 45980, 23360, 15196, 42894, 33054, 22073, 23786, 63308, 44883, 60088, 38633, 54798, 42893, 29049, 25567, 33563, 49913, 63714, 51666, 60112, 19656, 13133, 11756, 34277, 55622, 14539, 54580, 48536, 1337]

# Create sympy Matrix for M
A = Matrix(M)

# Create sympy Matrix for result (column vector)
b = Matrix(result)

# Solve Ax = b mod p
# Since p is prime, we can invert A mod p
try:
    A_inv = A.inv_mod(mod)
    x = (A_inv * b).applyfunc(lambda x: x % mod)
    
    # Convert x to bytes
    flag_bytes = []
    for val in x:
        flag_bytes.append(int(val))
    
    flag = bytes(flag_bytes)
    print(f"Flag: {flag.decode('utf-8', errors='ignore')}")
    print(f"Raw bytes: {flag}")

except Exception as e:
    print(f"Error: {e}")
```

### Step 4: Code Explanation

**Line-by-line breakdown:**

1. **Imports:**
   ```python
   from M import M
   from sympy import Matrix
   ```
   - Import the transformation matrix from `M.py`
   - Import SymPy's Matrix class for algebraic operations

2. **Setup:**
   ```python
   mod = 0x10001
   result = [29839, 662, ...]
   ```
   - Define the modulus (65537)
   - Define the encrypted result vector

3. **Matrix Creation:**
   ```python
   A = Matrix(M)
   b = Matrix(result)
   ```
   - Convert the Python list matrix to a SymPy Matrix object
   - Convert the result list to a column vector Matrix

4. **Matrix Inversion:**
   ```python
   A_inv = A.inv_mod(mod)
   ```
   - Compute M⁻¹ mod 65537
   - This uses the extended Euclidean algorithm internally
   - The operation is guaranteed to succeed if det(M) ≠ 0 (mod 65537)

5. **Solving for the Flag:**
   ```python
   x = (A_inv * b).applyfunc(lambda x: x % mod)
   ```
   - Multiply the inverse matrix with the result vector
   - Apply modulo operation to ensure values are in range [0, 65536]
   - This gives us the original flag bytes as integers

6. **Conversion to ASCII:**
   ```python
   flag_bytes = []
   for val in x:
       flag_bytes.append(int(val))
   
   flag = bytes(flag_bytes)
   print(f"Flag: {flag.decode('utf-8', errors='ignore')}")
   ```
   - Extract integer values from the SymPy Matrix
   - Convert to a bytes object
   - Decode as UTF-8 to get the flag string

### Step 5: Running the Solution

Execute the solution:

```bash
python3 solve.py
```

**Output:**
```
Flag: ctf{s0lve_th3_equ4t10n5_t0_f1nd_fl4g_h3r3_w4s_easy_en0ugh_NO???}
Raw bytes: b'ctf{s0lve_th3_equ4t10n5_t0_f1nd_fl4g_h3r3_w4s_easy_en0ugh_NO???}'
```

## Security Analysis

### Why This Cipher is Insecure

1. **Linear Transformation:** The encryption is purely linear, making it vulnerable to:
   - Known-plaintext attacks
   - Chosen-plaintext attacks
   - Algebraic attacks

2. **Single Round:** Modern ciphers use multiple rounds to increase security. This uses only one transformation.

3. **No Key Mixing:** There's no secret key component that remains hidden. The entire transformation is public.

4. **Deterministic:** Given the same input, it always produces the same output (no IV or nonce).

5. **Mathematically Reversible:** The encryption is trivially reversible with basic linear algebra.

## Key Takeaways

1. **Linear Algebra in Cryptography:** Understanding matrix operations and modular arithmetic is essential for cryptanalysis.

2. **The Importance of Non-Linearity:** Modern ciphers combine linear and non-linear operations for security. Pure linear transformations are easily broken.

3. **Known vs. Secret Components:** Encryption security should rely on secret keys, not secret algorithms (Kerckhoffs's principle).

4. **Tool Selection:** Libraries like SymPy make complex mathematical operations (like matrix inversion over finite fields) straightforward.

5. **Classical Methods:** Sometimes "classical" mathematical techniques (like matrix inversion) are sufficient to break a cipher, hence the challenge name "Classically."

## Conclusion

The "Classically" challenge demonstrates a fundamental principle in cryptography: **linear transformations alone do not provide security**. While matrix multiplication over finite fields forms the basis of some cryptographic schemes (like lattice-based cryptography), they must be combined with additional security measures to be effective.

The challenge was straightforward for anyone familiar with linear algebra and modular arithmetic, requiring only:
- Understanding of matrix operations
- Knowledge of modular inverses
- Ability to use appropriate mathematical libraries

The challenge name "Classically" is a clever hint, suggesting that classical (traditional) mathematical methods - specifically solving systems of linear equations - are the key to solving it. It's also a play on "classical" vs "quantum" computing, suggesting this is a problem easily solvable with classical computational methods.

Pwned!

KOREONE
