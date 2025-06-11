#ifndef ZKP_ENC_PROOF_H
#define ZKP_ENC_PROOF_H

#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Ciphertext.h"

using namespace mcl::bn;
class Proof{
    protected:
    Proof();
    public:
    typedef std::vector<ELGL_PK::Random_C> Random_C;

    const ELGL_PK* pk;
    int n_proofs;

    Plaintext challenge;
    Proof(const ELGL_PK& pk, int n_proofs = 1): pk(&pk), n_proofs(n_proofs){};

    virtual ~Proof() {}

    void set_challenge(const std::stringstream& ciphertexts);
    // void set_challenge(PRNG& G);
    // void generate_challenge(const Player& P);
};
#endif