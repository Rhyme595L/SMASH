#ifndef _FFT
#define _FFT

#include <mcl/bls12_381.hpp>
#include "libelgl/elgl/BLS12381Element.h"
#include <vector>

/**
 * @param input 
 * @param output 
 * @param alpha 
 * @param N 
 */
void FFT(const std::vector<BLS12381Element>& input, 
    std::vector<BLS12381Element>& output, 
    const Fr& alpha, 
    size_t N);
// void IFFT(const std::vector<BLS12381Element>& input, 
//     std::vector<BLS12381Element>& output, 
//     const Fr& alpha, 
//     size_t N);

void FFT_Para(const std::vector<BLS12381Element>& input, std::vector<BLS12381Element>& output, const Fr &omega, size_t n);

#endif