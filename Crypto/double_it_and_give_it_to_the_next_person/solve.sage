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
