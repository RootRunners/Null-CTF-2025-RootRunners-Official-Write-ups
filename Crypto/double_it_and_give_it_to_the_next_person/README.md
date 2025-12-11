# NullCTF 2025 - double_it_and_give_it_to_the_next_person Challenge Writeup

**Author:** infernosalex  
**Difficulty:** Medium  
**Category:** Cryptography

## Challenge Description

In Romanian folklore, there is a tradition called "dubleza si da mai departe" (double it and give it to the next person). This challenge is inspired by that tradition, but with a cryptographic twist.

## Intro

This challenge presents a cryptographic system based on elliptic curve cryptography (ECC) where two secret keys (`key1` and `key2`) are hidden within linear equations involving x-coordinates of elliptic curve points. The challenge uses the NIST P-256 elliptic curve and exploits the relationship between a point P and its double Q = 2P on the curve.

The vulnerability lies in the algebraic relationship between P and Q on an elliptic curve. When given multiple instances of linear masking of their x-coordinates, we can construct polynomial equations that encode the point-doubling constraint. Using computational algebraic geometry techniques, specifically Gröbner basis computation, we can solve this system of polynomial equations to recover the secret keys.

## Initial Analysis

The challenge code (chal.sage) generates the cryptographic puzzle:

```sage
p = 2**256-2**224+2**192+2**96-1
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

Zp = Zmod(p)
P256 = EllipticCurve(Zp, [a, b])

key1 = Zp.random_element()
key2 = Zp.random_element()

with open('output.txt', 'w') as f:
    for _ in range(2):
        P = P256.random_point()
        Q = 2*P

        b = Zp.random_element()
        a = (P.xy()[0] - b) / key1

        d = Zp.random_element()
        c = (Q.xy()[0] - d) / key2

        f.write(f"P.x = {a} * key1 + {b}\n")
        f.write(f"Q.x = {c} * key2 + {d}\n")

with open('flag', 'w') as f:
    key = int(key1) ^^ int(key2)
    f.write(f"nullctf{{{key:064x}}}")
```

**Key observations:**
- The curve used is NIST P-256 with the standard parameters
- Two random secret keys (`key1` and `key2`) are generated
- For each iteration, a random point P is selected and Q = 2P is computed
- The x-coordinates of P and Q are linearly masked: `P.x = a * key1 + b` and `Q.x = c * key2 + d`
- The flag is constructed by XORing the two keys: `flag = key1 ⊕ key2`

### output.txt

The challenge provides two instances of the masked coordinates:

```
P.x = 101391067652419278504279072061964396163420598174591672104811496061093042423713 * key1 + 110183945624921546387413554986656742713737778649772602611818367446708850272293
Q.x = 43935985468030112938420167350551592897480789520688041577831275174910738854569 * key2 + 13245902077735905939963311540878792271896625592735457462639747889134751588655
P.x = 113113920295449343615508981422751944711310245958533784150505930220126533492423 * key1 + 3292039546575820821367398987680176504505470559384412397685623175088154966631
Q.x = 90189751456536603500768763858048652235807590023038279530146107092251468907921 * key2 + 93980984745553841375952018332854663310402153214300203815947697055365029221289
```

## Vulnerability Analysis

### The Point-Doubling Formula

On an elliptic curve E: y² = x³ + ax + b, when doubling a point P = (xₚ, yₚ) to get Q = 2P = (xᵩ, yᵩ), the relationship between the x-coordinates follows from the elliptic curve addition formula:

The slope of the tangent line at P is:
```
λ = (3xₚ² + a) / (2yₚ)
```

The x-coordinate of the doubled point is:
```
xᵩ = λ² - 2xₚ
```

Substituting λ:
```
xᵩ = ((3xₚ² + a) / (2yₚ))² - 2xₚ
```

Since P lies on the curve: yₚ² = xₚ³ + axₚ + b

We can eliminate yₚ and derive a polynomial relation between xₚ and xᵩ:

```
(xᵩ + 2xₚ) · 4 · (xₚ³ + axₚ + b) = (3xₚ² + a)²
```

This is a **pure algebraic constraint** that must hold for any point P and its double Q = 2P on the curve, independent of the y-coordinates.

### Exploiting the Vulnerability

Given the linear masks:
- xₚ = a₁ · key1 + b₁
- xᵩ = c₁ · key2 + d₁

We can substitute these expressions into the point-doubling constraint to obtain a polynomial equation in two variables (key1, key2). 
With two such instances from the output, we get:

1. From instance 1: f₁(key1, key2) = 0
2. From instance 2: f₂(key1, key2) = 0

This forms a system of two polynomial equations in two unknowns over the finite field GF(p).

### Solution Approach: Gröbner Basis

To solve this system of polynomial equations, we use **Gröbner basis** computation with lexicographic monomial ordering.

This powerful technique from computational algebraic geometry allows us to:

1. Transform the system into a triangular form
2. Obtain a univariate polynomial in one variable
3. Solve the univariate polynomial to find candidate solutions
4. Back-substitute to find the other variable

The lexicographic ordering (lex order) ensures that one variable is eliminated first, producing a polynomial in a single variable that can be solved directly.

## Solution Implementation

### solve.sage

Here's the complete solution script:

```python
p = 2**256-2**224+2**192+2**96-1
a_curve = -3
b_curve = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

# Data from output.txt
data = [
    {
        'a': 101391067652419278504279072061964396163420598174591672104811496061093042423713,
        'b': 110183945624921546387413554986656742713737778649772602611818367446708850272293,
        'c': 43935985468030112938420167350551592897480789520688041577831275174910738854569,
        'd': 13245902077735905939963311540878792271896625592735457462639747889134751588655
    },
    {
        'a': 113113920295449343615508981422751944711310245958533784150505930220126533492423,
        'b': 3292039546575820821367398987680176504505470559384412397685623175088154966631,
        'c': 90189751456536603500768763858048652235807590023038279530146107092251468907921,
        'd': 93980984745553841375952018332854663310402153214300203815947697055365029221289
    }
]

# Use lexicographic order to eliminate variables
# k1 > k2, so k1 will be eliminated, leaving a polynomial in k2
R.<k1, k2> = PolynomialRing(GF(p), order='lex')

polys = []

for item in data:
    # P.x = a * k1 + b
    xp = item['a'] * k1 + item['b']
    # Q.x = c * k2 + d
    xq = item['c'] * k2 + item['d']
    
    # Relation: (xQ + 2xP) * 4 * (xP^3 + a_curve * xP + b_curve) = (3xP^2 + a_curve)^2
    lhs = (xq + 2*xp) * 4 * (xp**3 + a_curve * xp + b_curve)
    rhs = (3*xp**2 + a_curve)**2
    
    polys.append(lhs - rhs)

print("Computing Groebner basis with lex order...")
I = Ideal(polys)
B = I.groebner_basis()

print("Basis computed.")
for poly in B:
    print(f"Poly in vars {poly.variables()}: degree {poly.degree()}")
    if len(poly.variables()) == 1:
        var = poly.variables()[0]
        print(f"Univariate polynomial in {var}")
        
        # Cast to univariate polynomial ring
        R_uni = PolynomialRing(GF(p), var)
        poly_uni = R_uni(poly)
        
        # Solve univariate
        roots = poly_uni.roots()
        print(f"Roots for {var}: {roots}")
        
        for root, mult in roots:
            print(f"Trying {var} = {root}")
            
            if var == k2:
                val_k2 = root
                # Find k1
                for p_basis in B:
                    if k1 in p_basis.variables():
                        p_sub = p_basis.substitute(k2=val_k2)
                        # Cast to univariate in k1
                        R_k1 = PolynomialRing(GF(p), 'k1')
                        p_sub_uni = R_k1(p_sub)
                        roots_k1 = p_sub_uni.roots()
                        for r1, m1 in roots_k1:
                            val_k1 = r1
                            print(f"Found solution: k1={val_k1}, k2={val_k2}")
                            key = int(val_k1) ^^ int(val_k2)
                            print(f"Flag candidate: nullctf{{{key:064x}}}")
            elif var == k1:
                val_k1 = root
                # Find k2
                for p_basis in B:
                    if k2 in p_basis.variables():
                        p_sub = p_basis.substitute(k1=val_k1)
                        # Cast to univariate in k2
                        R_k2 = PolynomialRing(GF(p), 'k2')
                        p_sub_uni = R_k2(p_sub)
                        roots_k2 = p_sub_uni.roots()
                        for r2, m2 in roots_k2:
                            val_k2 = r2
                            print(f"Found solution: k1={val_k1}, k2={val_k2}")
                            key = int(val_k1) ^^ int(val_k2)
                            print(f"Flag candidate: nullctf{{{key:064x}}}")
```

### Step-by-Step Breakdown

1. **Setup the polynomial ring:**
   ```python
   R.<k1, k2> = PolynomialRing(GF(p), order='lex')
   ```
   We create a polynomial ring over GF(p) with variables k1 and k2, using lexicographic ordering.

2. **Construct the polynomial equations:**
   For each data instance, we substitute the linear expressions for xₚ and xᵩ into the point-doubling constraint:
   ```python
   xp = item['a'] * k1 + item['b']
   xq = item['c'] * k2 + item['d']
   
   lhs = (xq + 2*xp) * 4 * (xp**3 + a_curve * xp + b_curve)
   rhs = (3*xp**2 + a_curve)**2
   
   polys.append(lhs - rhs)
   ```

3. **Compute the Gröbner basis:**
   ```python
   I = Ideal(polys)
   B = I.groebner_basis()
   ```
   The Gröbner basis transforms our system into a more tractable form.

4. **Extract and solve univariate polynomials:**
   The Gröbner basis with lex ordering produces polynomials where some have only one variable. We find these univariate polynomials, solve them, and back-substitute to find both keys.

5. **Compute the flag:**
   ```python
   key = int(val_k1) ^^ int(val_k2)
   print(f"Flag candidate: nullctf{{{key:064x}}}")
   ```

### Execution Output

Running `sage solve.sage` produces:

```
Computing Groebner basis with lex order...
Basis computed.
Poly in vars (k1, k2): degree 6
Poly in vars (k2,): degree 7
Univariate polynomial in k2
Roots for k2: [(84695295895626745258083096842436371081628517837438655058953419374841100951788, 1), (36271322595383647980020150093010480435179262159729294394405400805566145335630, 1)]
Trying k2 = 84695295895626745258083096842436371081628517837438655058953419374841100951788
...
Found solution: k1=53158128764546402430481690719678660537805349221457847302543571892794642303820, k2=36271322595383647980020150093010480435179262159729294394405400805566145335630
Flag candidate: nullctf{25b6b8151d54b7f9e5fc3181e1d5b5a97464d019dde57aca90df349a8c951a02}
```

The Gröbner basis successfully reduced the system to a quadratic polynomial in k2, which has two roots. Testing the first root and back-substituting gives us both secret keys, and XORing them yields the flag.

## Flag

```
nullctf{25b6b8151d54b7f9e5fc3181e1d5b5a97464d019dde57aca90df349a8c951a02}
```

## Key Takeaways

1. **Algebraic structure of elliptic curves** provides powerful constraints that can be exploited when point relationships are known.

2. **Linear masking is insufficient** when the underlying algebraic relationship between masked values is preserved.

3. **Gröbner basis computation** is a powerful tool for solving systems of polynomial equations over finite fields, especially in cryptanalytic contexts.

4. **Two instances are enough:** With just two point-doubling instances, we have enough constraints to uniquely determine both secret keys.

5. **The vulnerability:** The core issue is that the point-doubling relationship creates a polynomial constraint between the masked x-coordinates. Multiple instances of this constraint allow complete key recovery through algebraic methods.

Pwned!

KOREONE
