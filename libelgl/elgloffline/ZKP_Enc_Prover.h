#ifndef ZKP_ENC_PROVER_H
#define ZKP_ENC_PROVER_H

#include "ZKP_Enc_Proof.h"
#include "libelgl/elgl/Ciphertext.h"
#include "emp-aby/utils.h"

class EncProver{
    std::vector <Plaintext> r1, r2;
    public:
    EncProver(Proof& proof);

    void NIZKPoK(Proof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts,
        const ELGL_PK& pk,
        const std::vector<Ciphertext>& c,
        const std::vector<Plaintext>& x,
        const Proof::Random_C& r, ThreadPool * pool);
    // size_t report_size();

    // void report_size(MemoryUsage& res);
};
#endif