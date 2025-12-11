
constants = [
    0xe6, 0xeb, 0xe5, 0xa0, 0x8e, 0xcb, 0xb0, 0xc8, 0xa1, 0x9d, 0xf3, 0xcc, 
    0xd0, 0xed, 0xe2, 0xe2, 0xdd, 0xd6, 0xd8, 0xd1, 0xdc, 0xe6, 0xa4, 0xb8, 
    0xfd, 0xbe
]

# Order from local test: 26 25 24 23 22 21 20 19 18 17 16 15 14 13 0 1 2 3 4 5 6 7 8 9 10 11 12
map_order = [
    26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
]

def solve_map_order():
    print("Trying map order...")
    
    for start_char_code in range(32, 127):
        v_vec = [0] * 27
        c = [0] * 27
        
        # v_vec[0] corresponds to map_order[0] = 26
        # Assume c[26] is start_char_code
        c[26] = start_char_code
        v_vec[0] = c[26] ^ 26
        
        valid = True
        for i in range(26):
            # constants[i] = v_vec[i] + v_vec[i+1]
            v_vec[i+1] = constants[i] - v_vec[i]
            
            # v_vec[i+1] corresponds to map_order[i+1]
            idx = map_order[i+1]
            # v_vec[i+1] = c[idx] ^ idx
            c[idx] = v_vec[i+1] ^ idx
            
            if not (32 <= c[idx] <= 126):
                valid = False
                break
        
        if valid:
            flag = "".join(chr(x) for x in c)
            print(f"Found flag (map order): {flag}")

solve_map_order()
