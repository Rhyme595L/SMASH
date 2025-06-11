#ifndef ROTATION_PROOF_H
#define ROTATION_PROOF_H

#include "libelgl/elgl/Ciphertext.h"

class RotationProof{
    protected:
    RotationProof();
    public:
    typedef Plaintext Randomness;

    const ELGL_PK* pk;
    const ELGL_PK* pk_tilde;

    const size_t n_tilde;

    Plaintext challenge;

    

    // protected:
    RotationProof(const ELGL_PK& pk, const ELGL_PK& pk_tilde, const size_t n_t) : pk(&pk), pk_tilde(&pk_tilde), n_tilde(n_t) {};

    virtual ~RotationProof() {}

    public:
    void set_challenge(const std::stringstream& ciphertexts);
    // void set_challenge(PRNG& G);
    // void generate_challenge(const Player& P);
  
};
#endif