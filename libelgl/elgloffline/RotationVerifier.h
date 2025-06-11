#ifndef ROTATION_VERIFIER_H
#define ROTATION_VERIFIER_H

#include "RotationProof.h"
#include "emp-aby/utils.h"

class RotationVerifier{
    RotationProof &P;
    RotationProof::Randomness sigma, eta, phi;
    std::vector<RotationProof::Randomness> miu_k, niu_k, rou_k;

    public:
    RotationVerifier(RotationProof& proof);

    void NIZKPoK(std::vector<BLS12381Element> &dk, std::vector<BLS12381Element> &ek, std::vector<BLS12381Element> &ak, std::vector<BLS12381Element> &bk, std::stringstream& ciphertexts, std::stringstream& cleartexts, 
                const ELGL_PK& pk, const ELGL_PK& pk_tilde, ThreadPool * pool);

    size_t report_size(){
        size_t res = 0;
        res += sizeof(sigma);
        res += sizeof(eta);
        res += sizeof(phi);
        res += (sizeof(miu_k[0]) + sizeof(niu_k[0]) + sizeof(rou_k[0])) * miu_k.size();
        return res;
    }
};
#endif