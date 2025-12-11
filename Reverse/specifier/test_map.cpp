#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <algorithm>

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
