#include <vector>
#include <cassert>
#include "libelgl/elgl/FFT.h"
#include "libelgl/elgl/BLS12381Element.h"
#include <mcl/bls12_381.hpp>
#include "libelgl/elgl/Plaintext.h"
#include <chrono>
using namespace std;
void FFT_recursive_P(const std::vector<BLS12381Element>& a, std::vector<BLS12381Element>& A, const Fr &omega, size_t n) {
    if (n == 1) {
        A[0] = a[0];  
        return;
    }

    size_t m = n / 2;
    std::vector<BLS12381Element> a_even(m), a_odd(m);

    for (size_t i = 0; i < m; i++) {
        a_even[i] = a[2 * i];
        a_odd[i] = a[2 * i + 1];
    }

    std::vector<BLS12381Element> A_even(m), A_odd(m);

    Fr omegaSquared = omega * omega;

    #pragma omp parallel sections
    {
        #pragma omp section
        FFT_recursive_P(a_even, A_even, omegaSquared, m); 

        #pragma omp section
        FFT_recursive_P(a_odd, A_odd, omegaSquared, m); 
    }

    Fr w(1);
    for (size_t j = 0; j < m; j++) {
        BLS12381Element t = A_odd[j] * w;
        A[j] = A_even[j] + t;
        A[j + m] = A_even[j] - t;
        w *= omega;
    }
}

void FFT_P(const std::vector<BLS12381Element>& input, std::vector<BLS12381Element>& output, const Fr &omega, size_t n) {
    assert(n == input.size());
    output.resize(n);
    FFT_recursive_P(input, output, omega, n);
}

void parallel_FFT(std::vector<BLS12381Element>& a, const Fr& omega, size_t n) {
    #pragma omp parallel
    {
        #pragma omp for
        for (size_t i = 1; i < n; i++) {
            size_t j = 0;
            for (size_t k = n >> 1; !((j ^= k) & k); k >>= 1);
            if (i < j) {
                #pragma omp critical
                std::swap(a[i], a[j]);
            }
        }
    }

    std::vector<Plaintext> twiddle_factors(n/2);
    #pragma omp parallel
    {
        #pragma omp for
        for (size_t i = 0; i < n/2; i++) {
            Plaintext i_;
            i_.assign(to_string(i));
            Plaintext::pow(twiddle_factors[i], omega, i_);

        }
    }

    for (size_t m = 2; m <= n; m <<= 1) {
        size_t mh = m >> 1;
        size_t mq = n / m;
        
        #pragma omp parallel for schedule(guided)
        for (size_t i = 0; i < n; i += m) {
            for (size_t j = 0; j < mh; j++) {
                size_t k = j * mq; 
                BLS12381Element t = a[i + j + mh] * twiddle_factors[k].get_message();
                a[i + j + mh] = a[i + j] - t;
                a[i + j] += t;
            }
        }
    }
}

int main() {
    BLS12381Element::init();
    BLS12381Element G = BLS12381Element(1);

    mcl::Unit N = 65536; 
    Plaintext alpha; 

    mpz_class p = Fr::getOp().mp; 
    cout << "G1 群的阶 p: " << p.getStr(16) << endl;
    

    Plaintext g,exp;
    g.assign(5);
    cout << "g: " << g.get_message() << endl;

    exp.assign((p - 1)/N);
    cout << "exp = (p-1)/N: " << exp.get_message().getStr() << endl;


    Plaintext::pow(alpha, g, exp);
    cout << "alpha: " << alpha.get_message() << endl;

    Plaintext alpha_inv;
    Plaintext p_1;
    p_1.assign(p-1);
    Plaintext::pow(alpha_inv, g, p_1-exp);
    cout << "alpha_inv: " << alpha_inv.get_message() << endl;

    Plaintext result;
    result = alpha * alpha_inv;
    cout << "验证 alpha * alpha_inv: " << result.get_message() << endl;

    std::vector<BLS12381Element> input(N);
    for (size_t i = 0; i < N; ++i) {
        input[i] = G * i ; 
    }

    std::vector<BLS12381Element> output(N);
    std::vector<BLS12381Element> output_2(N);

    auto start = std::chrono::high_resolution_clock::now();
    FFT_P(input, output, alpha.get_message(), N);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "FFT 执行时间: " << duration.count() << " ms" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    FFT(input, output_2, alpha.get_message(), N);
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "FFT 执行时间: " << duration.count() << " ms" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    parallel_FFT(input, alpha.get_message(), N);
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "FFT 执行时间: " << duration.count() << " ms" << std::endl;


    for (size_t i = 0; i < N; ++i) {
        if (output[i] != output_2[i]) {
            std::cout << "Mismatch at index " << i << std::endl;
            return 1;
        }
    }

    for (size_t i = 0; i < N; i++)
    {
        if (output[i] != input[i]){
            std::cout << i << "错误" << std::endl;
            return 1;
        }
    }
    
}
