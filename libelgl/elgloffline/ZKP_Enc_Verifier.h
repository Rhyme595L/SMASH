#ifndef ZKP_ENC_VERIFIER_H
#define ZKP_ENC_VERIFIER_H

#include "ZKP_Enc_Proof.h"
#include "emp-aby/utils.h"
class EncVerifier{
    std::vector<Plaintext> sx, sr;
    Proof &P;
    public:
    EncVerifier(Proof& proof);

    void NIZKPoK(std::vector<Ciphertext>& c, std::stringstream& ciphertexts, std::stringstream& cleartexts,
                const ELGL_PK& pk, ThreadPool * pool);

    size_t report_size(){return sx.size() * Fr::getByteSize() + sr.size() * Fr::getByteSize();};
};

#endif