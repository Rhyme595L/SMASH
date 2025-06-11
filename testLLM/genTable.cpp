#include "FixedPointConverter.h"
#include <fstream>
#include <iostream>
#include <cmath>
#include <functional>
#include <string>
#include <experimental/filesystem>

using namespace std;

constexpr uint32_t TABLE_SIZE = FixedPointConverter::FIELD_SIZE;
const std::string OUTPUT_DIR = "./";

using ActivationFn = std::function<double(double)>;

void generate_table(const std::string& name, const ActivationFn& func) {
    std::string path = OUTPUT_DIR + "/table_" + name + ".txt";
    std::ofstream fout(path);
    if (!fout.is_open()) {
        std::cerr << "Failed to open file: " << path << std::endl;
        return;
    }

    std::cout << "[*] Generating " << name << "..." << std::endl;

    for (uint32_t i = 0; i < TABLE_SIZE; ++i) {
        double x = FixedPointConverter::decode(i);
        double y = func(x);
        uint64_t encoded_y = FixedPointConverter::encode(y);
        fout << encoded_y << '\n';
    }

    fout.close();
    std::cout << "[+] Done: " << path << std::endl;
}

int main() {
    std::experimental::filesystem::create_directories(OUTPUT_DIR);

    generate_table("relu", [](double x) -> double {
        return std::max(0.0, x);
    });

    generate_table("sigmoid", [](double x) -> double {
        return 1.0 / (1.0 + std::exp(-x));
    });

    generate_table("tanh", [](double x) -> double {
        return std::tanh(x);
    });

    generate_table("gelu", [](double x) -> double {
        return 0.5 * x * (1 + std::tanh(std::sqrt(2 / M_PI) * (x + 0.044715 * std::pow(x, 3))));
    });

    generate_table("sqrt", [](double x) -> double {
        return std::sqrt(std::max(0.0, x));
    });

    generate_table("div", [](double x) -> double {
        return x != 0.0 ? 1.0 / x : 0.0;
    });

    return 0;
}
