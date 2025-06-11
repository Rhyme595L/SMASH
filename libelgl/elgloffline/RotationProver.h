#ifndef ROTATION_PROVER_H
#define ROTATION_PROVER_H

#include "RotationProof.h"
#include "libelgl/elgl/Ciphertext.h"
#include "emp-aby/utils.h"
class RotationProver {
    RotationProof::Randomness m_tilde, b;
    std::vector<RotationProof::Randomness> mk, tk, uk, vk, m_tilde_k, yk;

    public:
    RotationProver(RotationProof& proof);

    size_t NIZKPoK(RotationProof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts, const ELGL_PK& pk, const ELGL_PK& pk_tilde, 
        const std::vector<BLS12381Element> dk, const std::vector<BLS12381Element> ek, const std::vector<BLS12381Element> ak,const std::vector<BLS12381Element> bk, Plaintext& beta, 
        const std::vector<Plaintext>& sk, ThreadPool* pool);
    
    size_t report_size();

    // void report_size(MemoryUsage& res);
};
#endif