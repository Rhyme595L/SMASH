#ifndef SCHNORR_PROOF_H
#define SCHNORR_PROOF_H

#include "libelgl/elgl/Ciphertext.h"


class Schnorr_Proof{
    protected:
    Schnorr_Proof();
    public:
    typedef Plaintext Randomness;
    
    const size_t n_tilde;
    const ELGL_PK* pk;

    Plaintext challenge;
    Schnorr_Proof(const ELGL_PK& pk, const size_t n_t) : n_tilde(n_t), pk(&pk) {};

    virtual ~Schnorr_Proof() {}

    void set_challenge(const std::stringstream& ciphertexts);
    // void set_challenge(PRNG& G);
    // void generate_challenge(const Player& P);
};

#endif