#include "FixedPointConverter.h"
#include <iostream>
#include <vector>
#include <iomanip>

int main() {
    std::vector<double> test_values = {
        -32, 1.0, -1.0, 3.14159, -2.71828,
        12345.6789, -12345.6789, 0.00001, -0.00001
    };

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "=== Q8.16 Fixed Point Encoding Test ===\n";

    for (double val : test_values) {
        uint64_t encoded = FixedPointConverter::encode(val);
        double decoded = FixedPointConverter::decode(encoded);

        std::cout << "Original: " << val
                  << " -> Encoded: " << encoded
                  << " -> Decoded: " << decoded << "\n";
    }
    return 0;
}
