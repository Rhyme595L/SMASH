#ifndef EXP_PROOF_H
#define EXP_PROOF_H

#include "libelgl/elgl/Ciphertext.h"

using namespace std;
class ExpProof{
    protected:
    ExpProof();
    public:
    typedef vector<Plaintext> Randomness;    
    const ELGL_PK* pk;

    int n_proofs;

    Plaintext challenge;

    // protected:
    ExpProof(const ELGL_PK& pk, int n_proofs = 1) : pk(&pk), n_proofs(n_proofs) {};

    virtual ~ExpProof() {}

    public:

    void set_challenge(const std::stringstream& ciphertexts);
    // void set_challenge(PRNG& G);
    // void generate_challenge(const Player& P);
};

#endif