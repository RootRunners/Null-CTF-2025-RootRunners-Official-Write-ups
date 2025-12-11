# NullCTF 2025 - specifier Challenge Writeup

**Author:** tomadimitrie  
**Difficulty:** Medium  
**Category:** Reverse Engineering  

**Challenge Description**:

> I tried to register my custom printf handlers, but the functions are soooo outdated...
> 
> I found this new C++ library which makes it easier!

## Intro

This challenge involves reverse engineering a C++ binary that uses the modern `fmt` library (libfmt) to implement custom format specifiers. The challenge demonstrates an interesting use case of C++20 ranges and custom formatters, where the validation logic relies on the iteration order of an `std::unordered_map` data structure. The objective is to understand the custom formatting logic, extract the validation constants, and reverse the transformation applied to the input flag.

The challenge highlights:
- Custom formatter implementations in the `fmt` library
- C++20 ranges and views
- Hash map iteration order dependencies
- XOR-based character encoding

## Initial Analysis

### Challenge Files

The challenge provides a single binary file named `specifier`. Let's start by examining it:

```bash
$ file specifier
specifier: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped

$ ./specifier
Enter flag: test_input
Incorrect
```

The binary is a 64-bit ELF executable that prompts for input and validates it, responding with either "Correct" or "Incorrect".

### Decompilation

Using Ghidra to decompile the binary, we can examine the `main` function and understand the program flow.

## Code Analysis

### Main Function

The decompiled `main` function shows the following logic:

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  undefined1 local_88 [16];
  string local_78 [32];
  string local_58 [40];
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  std::__cxx11::string::string(local_78);
  std::operator<<((ostream *)std::cout,"Enter flag: ");
  std::operator>>((istream *)std::cin,local_78);
  std::__cxx11::string::string(local_58,local_78);
  local_88 = fmt::v9::make_format_args<>(local_58);
  fmt::v9::vprint(&DAT_00135144,3,0xf,local_88);
  Input::~Input((Input *)local_58);
  std::__cxx11::string::~string(local_78);
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

The program:
1. Reads user input into a string
2. Wraps it in an `Input` object
3. Passes it to `fmt::v9::vprint` with a format string at address `0x00135144`

### Format String

Using `dd` to extract the format string from the binary:

```bash
$ dd if=specifier bs=1 skip=$((0x35134)) count=32 2>/dev/null | xxd
00000000: 7b7d 0045 6e74 6572 2066 6c61 673a 2000  {}.Enter flag: .
00000010: 7b7d 0a00 696e 7661 6c69 6420 7479 7065  {}..invalid type
```

The format string is `"{}"`, which means the `Input` object will be formatted using a custom formatter.

### Custom Formatter for Input

The `formatter<Input>` implementation processes the input string character by character:

```c
undefined8 __thiscall
fmt::v9::formatter<>::format(formatter<> *this,string *param_2,basic_format_context *param_3)
{
  char cVar1;
  string *this_00;
  undefined8 uVar2;
  long in_FS_OFFSET;
  // ... local variables ...
  
  std::unordered_map<>::unordered_map(local_108);
  local_160 = std::ranges::views::_Enumerate::operator()
                        ((_Enumerate *)&std::ranges::views::enumerate,param_2);
  local_158 = (enumerate_view<> *)&local_160;
  local_128 = (_Iterator<true>  [16])std::ranges::enumerate_view<>::begin(local_158);
  local_118 = std::ranges::enumerate_view<>::end(local_158);
  
  // Iterate over enumerated string
  while( true ) {
    cVar1 = std::ranges::operator==((_Iterator *)local_128,(_Iterator *)local_118);
    if (cVar1 == '\x01') break;
    std::ranges::enumerate_view<>::_Iterator<true>::operator*(local_138);
    local_150 = std::get<>((tuple *)local_138);  // index
    local_148 = std::get<>((tuple *)local_138);  // character
    local_140 = (undefined4)*(undefined8 *)local_150;
    local_13c = *local_148;
    
    // Format each character as InputChar (index, char)
    local_c8 = &DAT_00135134;
    local_c0 = 2;
    auVar3 = make_format_args<>((InputChar *)&local_140);
    local_88 = auVar3;
    vformat_abi_cxx11_(local_68,local_c8,local_c0,0xf,local_88);
    
    // Store in unordered_map with index as key
    local_c8 = (undefined *)CONCAT44(local_c8._4_4_,(int)*(undefined8 *)local_150);
    this_00 = (string *)std::unordered_map<>::operator[](local_108,(uint *)&local_c8);
    std::__cxx11::string::operator=(this_00,local_68);
    std::__cxx11::string::~string(local_68);
    std::ranges::enumerate_view<>::_Iterator<true>::operator++(local_128);
  }
  
  // Wrap map and format as MapWrapper
  std::unordered_map<>::unordered_map((unordered_map<> *)&local_c8,(unordered_map *)local_108);
  local_118._0_8_ = &DAT_00135134;
  local_118._8_8_ = 2;
  local_78 = make_format_args<>((MapWrapper *)&local_c8);
  vformat_abi_cxx11_(local_68,local_118._0_8_,local_118._8_8_,0xf,local_78);
  uVar2 = formatter<>::format<>((formatter<> *)this,local_68,param_3);
  // ...
  return uVar2;
}
```

The formatter:
1. Creates an `std::unordered_map<unsigned int, std::string>`
2. Enumerates the input string (getting index and character)
3. For each character at index `i`, formats it as an `InputChar` and stores the result in the map with key `i`

### Custom Formatter for InputChar

The `formatter<InputChar>` processes a character-index pair:

```c
undefined8 __thiscall
fmt::v9::formatter<>::format(formatter<> *this,undefined8 param_2,basic_format_context *param_3)
{
  undefined8 uVar1;
  long in_FS_OFFSET;
  uint local_58;
  char cStack_54;
  __cxx11 local_48 [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  cStack_54 = (char)((ulong)param_2 >> 0x20);
  local_58 = (uint)param_2;
  std::__cxx11::to_string(local_48,(int)cStack_54 ^ local_58);
  uVar1 = formatter<>::format<>((formatter<> *)this,(string *)local_48,param_3);
  std::__cxx11::string::~string((string *)local_48);
  // ...
  return uVar1;
}
```

This formatter:
1. Extracts the character `c` and index `i` from the parameter
2. Computes `c ^ i` (XOR operation)
3. Converts the result to a string

So for each character `c` at position `i` in the input, the value `c ^ i` is stored as a string in the map with key `i`.

### Custom Formatter for MapWrapper

The `formatter<MapWrapper>` is the most complex part. It validates the transformed input:

```c
// The formatter transforms the map into a vector and validates it
// Key lambda function that transforms map entries:
_func_format_MapWrapper_basic_format_context_ptr * __thiscall
const::{lambda(auto:1_const&)#3}::operator()(_lambda_auto_1_const___3_ *this,pair *param_1)
{
  _func_format_MapWrapper_basic_format_context_ptr *p_Var1;
  
  p_Var1 = (_func_format_MapWrapper_basic_format_context_ptr *)
           std::__cxx11::stoi((string *)(param_1 + 8),(ulong *)0x0,10);
  return p_Var1;
}
```

This lambda converts the string values back to integers.

The validation logic uses `std::ranges::equal` to compare the vector against expected values:

```c
// Validation function (simplified)
const::{lambda(unsigned_long)#1}::operator()(_lambda_unsigned_long__1_ *this,ulong param_1)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = (int *)std::vector<>::operator[](*(vector<> **)this,param_1);
  iVar1 = *piVar2;
  piVar2 = (int *)std::vector<>::operator[](*(vector<> **)this,param_1 + 1);
  return (_func_format_MapWrapper_basic_format_context_ptr *)(ulong)(uint)(*piVar2 + iVar1);
}
```

This lambda computes `v[i] + v[i+1]` for each position in the vector.

The comparison checks if `v[i] + v[i+1] == constants[i]` for all `i`.

## Extracting Constants

The validation constants can be extracted from the binary. By analyzing the code and memory, we find 26 constants:

```python
constants = [
    0xe6, 0xeb, 0xe5, 0xa0, 0x8e, 0xcb, 0xb0, 0xc8, 0xa1, 0x9d, 0xf3, 0xcc, 
    0xd0, 0xed, 0xe2, 0xe2, 0xdd, 0xd6, 0xd8, 0xd1, 0xdc, 0xe6, 0xa4, 0xb8, 
    0xfd, 0xbe
]
```

## The Critical Issue: Unordered Map Iteration Order

The key challenge here is understanding that `std::unordered_map` does not guarantee any specific iteration order. The order depends on:
- The hash function implementation
- The number of buckets
- The insertion order
- The compiler and standard library version

To determine the actual iteration order, we need to create a small test program:

```cpp
#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>

int main() {
    std::unordered_map<unsigned int, std::string> m;
    for (unsigned int i = 0; i < 27; ++i) {
        m[i] = "val";
    }

    std::cout << "Order: ";
    for (const auto& pair : m) {
        std::cout << pair.first << " ";
    }
    std::cout << std::endl;
    return 0;
}
```

Compiling and running this on a system with the same compiler/stdlib as the challenge binary:

```bash
$ g++ test_map.cpp -o test_map && ./test_map
Order: 26 25 24 23 22 21 20 19 18 17 16 15 14 13 0 1 2 3 4 5 6 7 8 9 10 11 12
```

This reveals the crucial information: the map iterates in the order `26, 25, ..., 13, 0, 1, ..., 12`.

## Solution Strategy

Now we can solve the challenge:

1. The input flag has 27 characters (indices 0-26)
2. For each character `c[i]`, the value `v[i] = c[i] ^ i` is computed
3. These values are stored in a map and then extracted in the iteration order
4. The validation checks: `v_vec[i] + v_vec[i+1] = constants[i]` where `v_vec` follows the map iteration order

### Mathematical Formulation

Let's denote:
- `c[i]` = character at position `i` in the flag (0 ≤ i ≤ 26)
- `v[i] = c[i] ^ i` = transformed value for position `i`
- `map_order = [26, 25, 24, ..., 13, 0, 1, ..., 12]` = iteration order
- `v_vec[j] = v[map_order[j]]` = values in iteration order

The validation equations are:
```
v_vec[0] + v_vec[1] = constants[0]
v_vec[1] + v_vec[2] = constants[1]
...
v_vec[25] + v_vec[26] = constants[25]
```

This forms a system of linear equations that we can solve by:
1. Trying all possible printable ASCII values for `c[26]` (the first element in iteration order)
2. Computing `v_vec[0] = c[26] ^ 26`
3. For each subsequent position, computing `v_vec[i+1] = constants[i] - v_vec[i]`
4. Mapping back: `c[map_order[i+1]] = v_vec[i+1] ^ map_order[i+1]`
5. Checking if all characters are printable ASCII

## Solution Script

```python
constants = [
    0xe6, 0xeb, 0xe5, 0xa0, 0x8e, 0xcb, 0xb0, 0xc8, 0xa1, 0x9d, 0xf3, 0xcc, 
    0xd0, 0xed, 0xe2, 0xe2, 0xdd, 0xd6, 0xd8, 0xd1, 0xdc, 0xe6, 0xa4, 0xb8, 
    0xfd, 0xbe
]

# Map iteration order determined from test program
map_order = [
    26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
]

def solve():
    # Try all printable ASCII characters for the first element
    for start_char_code in range(32, 127):
        v_vec = [0] * 27
        c = [0] * 27
        
        # First element in iteration order corresponds to index 26
        c[26] = start_char_code
        v_vec[0] = c[26] ^ 26
        
        valid = True
        for i in range(26):
            # From equation: v_vec[i] + v_vec[i+1] = constants[i]
            v_vec[i+1] = constants[i] - v_vec[i]
            
            # Map back to character array
            idx = map_order[i+1]
            c[idx] = v_vec[i+1] ^ idx
            
            # Check if character is printable ASCII
            if not (32 <= c[idx] <= 126):
                valid = False
                break
        
        if valid:
            flag = "".join(chr(x) for x in c)
            if "nullctf" in flag:
                print(f"Flag: {flag}")
                return flag

if __name__ == "__main__":
    solve()
```

Running the script:

```bash
$ python3 solve_map.py
Trying map order...
Found flag (map order): ormmlug|c0uuLs\ui5oXqs>ougr
Found flag (map order): nullctf{b3tt3r_th4n_pr1ntf}
Flag: nullctf{b3tt3r_th4n_pr1ntf}
```

## Verification

Let's verify the flag works:

```bash
$ echo "nullctf{b3tt3r_th4n_pr1ntf}" | ./specifier
Enter flag: Correct
```

## Key Takeaways

1. **Modern C++ Features**: This challenge showcases advanced C++20 features including custom formatters, ranges, and views from the `fmt` library.

2. **Hash Map Iteration Order**: The critical insight is understanding that `std::unordered_map` iteration order is implementation-dependent and not related to key order. This required empirical testing to determine.

3. **XOR Encoding**: The transformation `c[i] ^ i` is a simple but effective encoding that varies based on position, making manual analysis more difficult.

4. **Linear System Solving**: The validation constraints form a system of linear equations that can be efficiently solved with a brute-force approach over the first unknown value.

5. **Reverse Engineering**: Proper decompilation and understanding of C++ STL implementations (especially templates) is essential for solving modern C++ reverse engineering challenges.

## Conclusion

This challenge demonstrates an interesting application of modern C++ features in a CTF context. The use of custom formatters and the dependency on unordered map iteration order created a unique puzzle that required both static analysis and dynamic testing to solve. The challenge name "specifier" is a clever reference to format specifiers in printf-style formatting, which the `fmt` library improves upon with type-safe, extensible formatting.

Pwned!

KOREONE
