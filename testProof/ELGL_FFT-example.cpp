#include "libelgl/elgl/FFT.h"
#include "libelgl/elgl/Plaintext.h"
#include "libelgl/elgl/BLS12381Element.h"
#include <iostream>
#include <chrono>
using namespace std;
int main() {
    BLS12381Element::init();
    BLS12381Element G = BLS12381Element(1);

    // 设置 FFT 的参数
    mcl::Unit N = 65536; // FFT 长度，必须为 2 的幂次
    Plaintext alpha; // 阶为 N 的模Fr元素

    // 获取 G1 群的阶 p
    mpz_class p = Fr::getOp().mp; 
    
    Plaintext g,exp;
    g.assign(5);
    cout << "g: " << g.get_message() << endl;

    exp.assign((p - 1)/N);
    cout << "exp = (p-1)/N: " << exp.get_message().getStr() << endl;

    // 计算 alpha = g^exp
    Plaintext::pow(alpha, g, exp);
    cout << "alpha: " << alpha.get_message() << endl;

    Plaintext alpha_inv;
    Plaintext p_1;
    p_1.assign(p-1);
    Plaintext::pow(alpha_inv, g, p_1-exp);
    cout << "alpha_inv: " << alpha_inv.get_message() << endl;

    // 输入序列
    std::vector<BLS12381Element> input(N);
    for (size_t i = 0; i < N; ++i) {
        input[i] = G * i ; 
    }

    // 输出序列
    std::vector<BLS12381Element> output(N);
    std::vector<BLS12381Element> output_p(N);

    // 执行 FFT
    auto start = std::chrono::high_resolution_clock::now();
    FFT(input, output, alpha.get_message(), N);
    auto end = std::chrono::high_resolution_clock::now();    // 记录结束时间
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    FFT_Para(input, output_p, alpha.get_message(), N);
    end = std::chrono::high_resolution_clock::now();    // 记录结束时间
    duration = end - start;
    std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;

    // check if output == output_p
    std::cout << "验证 FFT 结果是否相同：" << std::endl;
    for (size_t i = 0; i < N; ++i) {
        if (output[i]!= output_p[i]){
            std::cout << i << "错误" << std::endl;
            return 1;
        }
    }
    // 计算逆 FFT
    std::vector<BLS12381Element> inverse_output(N);

    // IFFT(output, inverse_output, alpha.get_message(), N);
    // Fr N_inv;
    // Fr::inv(N_inv, Fr(N));
    // cout << "N: " << N << endl;
    // cout << "N_inv: " << N_inv << endl;
    // cout << "N * N_inv: " << N * N_inv << endl;

    // start = std::chrono::high_resolution_clock::now();
    // FFT(output, inverse_output, alpha_inv.get_message(), N);
    // end = std::chrono::high_resolution_clock::now();    // 记录结束时间
    // duration = end - start;
    // std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;
    // for(size_t i = 0; i < N; i++){
    //     inverse_output[i] = inverse_output[i] * N_inv;
    // }
    
    // // 验证逆 FFT 结果是否与输入相同
    // std::cout << "验证逆 FFT 结果是否与输入相同：" << std::endl;
    // for (size_t i = 0; i < N; ++i) {
    //     if (inverse_output[i] != input[i]){
    //         std::cout << i << "错误" << std::endl;
    //         return 1;
    //     }
    // }
    // std::cout << "验证成功" << std::endl;
    return 0;
}