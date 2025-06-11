#ifndef COMM_PROOF_H
#define COMM_PROOF_H

#include "libelgl/elgl/Ciphertext.h"
#include <vector>

using namespace std;
class CommProof{
    protected:
    CommProof();
    public:
    typedef vector<Plaintext> Randomness;    
    const ELGL_PK* pk;

    int n_proofs;

    Plaintext challenge;

    // protected:
    CommProof(const ELGL_PK& pk, int n_proofs = 1) : pk(&pk), n_proofs(n_proofs) {};

    virtual ~CommProof() {}

    public:

    void set_challenge(std::stringstream& ciphertexts);
    // void set_challenge(RNG& G);
};

#endif