#include <mcl/bls12_381.hpp>
#include <iostream>

using namespace mcl::bn;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cout << "Usage: ./calPoint <Fr>" << std::endl;
        return 1;
    }

    // 初始化 BLS12-381 配对
    initPairing(mcl::BLS12_381);

    // 将命令行参数赋值给 Fr
    Fr x;
    if (!x.setStr(argv[1])) {
        std::cerr << "Invalid Fr value: " << argv[1] << std::endl;
        return 1;
    }

    // 计算 g^x
    G1 g = getG1BasePoint(); // 获取 G1 基点
    G1 result;
    G1::mul(result, g, x); // 计算 g^x

    // 输出结果
    std::cout << "g^x = " << result.getStr() << std::endl;

    return 0;
}