#pragma once
#include <vector>
#include <cassert>
#include <future>
#include "BLS12381Element.h"
#include <mcl/bn.hpp>

using namespace mcl::bn;

void FFT_recursive_para(
    const std::vector<BLS12381Element>& a,
    std::vector<BLS12381Element>& A,
    const Fr& omega,
    size_t n,
    int depth = 2
) {
    if (n == 1) {
        A[0] = a[0];
        return;
    }

    size_t m = n / 2;
    std::vector<BLS12381Element> a_even(m), a_odd(m);
    std::vector<BLS12381Element> A_even(m), A_odd(m);

    for (size_t i = 0; i < m; ++i) {
        a_even[i] = a[2 * i];
        a_odd[i] = a[2 * i + 1];
    }

    Fr omega_squared = omega * omega;

    if (depth > 0) {
        auto fut_even = std::async(std::launch::async, FFT_recursive_para, std::cref(a_even), std::ref(A_even), omega_squared, m, depth - 1);
        FFT_recursive_para(a_odd, A_odd, omega_squared, m, depth - 1);
        fut_even.get();
    } else {
        FFT_recursive_para(a_even, A_even, omega_squared, m, 0);
        FFT_recursive_para(a_odd, A_odd, omega_squared, m, 0);
    }

    Fr w = 1;
    for (size_t j = 0; j < m; ++j) {
        BLS12381Element t = A_odd[j] * w;
        A[j] = A_even[j] + t;
        A[j + m] = A_even[j] - t;
        w *= omega;
    }
}

void FFT_Para(
    const std::vector<BLS12381Element>& input,
    std::vector<BLS12381Element>& output,
    const Fr& omega,
    size_t n
) {
    assert((n & (n - 1)) == 0); 
    assert(n == input.size());
    output.resize(n);
    FFT_recursive_para(input, output, omega, n, 3);
}

void IFFT_Para(
    const std::vector<BLS12381Element>& input,
    std::vector<BLS12381Element>& output,
    const Fr& omega,
    size_t n
) {
    Fr omega_inv;
    Fr::inv(omega_inv, omega);
    FFT_Para(input, output, omega_inv, n);
    Fr inv_n;
    Fr::inv(inv_n, Fr(n));
    for (auto& e : output) {
        e *= inv_n;
    }
}
