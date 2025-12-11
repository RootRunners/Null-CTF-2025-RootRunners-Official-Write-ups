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
