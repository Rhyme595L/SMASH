// FFT_IFFT_example.cpp
#include <iostream>
#include <vector>
#include <cassert>
#include "BLS12381Element.h" 
#include "Plaintext.h"
#include <mcl/bn.hpp>

#include <future>

using namespace std;
using namespace mcl::bn;

/**
 * @param a 
 * @param A
 * @param omega 
 * @param n 
 */
void FFT_recursive(const vector<BLS12381Element>& a, vector<BLS12381Element>& A, const Fr &omega, size_t n) {
    if (n == 1) {
        A[0] = a[0];  
        return;
    }
    size_t m = n / 2;
    vector<BLS12381Element> a_even(m), a_odd(m);
    for (size_t i = 0; i < m; i++) {
        a_even[i] = a[2 * i];
        a_odd[i] = a[2 * i + 1];
    }
    vector<BLS12381Element> A_even(m), A_odd(m);
    Fr omegaSquared = omega * omega;
    FFT_recursive(a_even, A_even, omegaSquared, m);
    FFT_recursive(a_odd, A_odd, omegaSquared, m);
    Fr w(1); 
    for (size_t j = 0; j < m; j++) {
        BLS12381Element t = A_odd[j] * w;
        A[j] = A_even[j] + t;
        A[j + m] = A_even[j] - t;
        w *= omega;
    }
}

void FFT(const vector<BLS12381Element>& input, vector<BLS12381Element>& output, const Fr &omega, size_t n) {
    assert(n == input.size());
    output.resize(n);
    FFT_recursive(input, output, omega, n);
}

void FFT_recursive_para(const std::vector<BLS12381Element>& a, std::vector<BLS12381Element>& A, const Fr &omega, size_t n) {
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
    
    auto future_even = std::async(std::launch::async, [&]() {
        FFT_recursive(a_even, A_even, omegaSquared, m);
    });
    auto future_odd = std::async(std::launch::async, [&]() {
        FFT_recursive(a_odd, A_odd, omegaSquared, m);
    });
    future_even.get();
    future_odd.get();
    
    Fr w(1); 
    for (size_t j = 0; j < m; j++) {
        BLS12381Element t = A_odd[j] * w;
        A[j] = A_even[j] + t;
        A[j + m] = A_even[j] - t;
        w *= omega;
    }
}

void FFT_Para(const std::vector<BLS12381Element>& input, std::vector<BLS12381Element>& output, const Fr &omega, size_t n) {
    assert(n == input.size());
    output.resize(n);
    FFT_recursive_para(input, output, omega, n);
}