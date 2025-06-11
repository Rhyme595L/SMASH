#ifndef RANGE_PROOF_H
#define RANGE_PROOF_H

#include "libelgl/elgl/Ciphertext.h"

class RangeProof{
    protected:
    RangeProof();
    public:
    typedef std::vector<Plaintext> Randomness;
    
    const ELGL_PK* pk;

    size_t n_proofs;

    Plaintext challenge;

    mpz_class bound;

    RangeProof(const ELGL_PK& pk, const mpz_class& b, size_t n_proofs = 1) : pk(&pk), n_proofs(n_proofs), bound(b) {};

    // protected:
    virtual ~RangeProof() {}

    public:

    void set_challenge(const std::stringstream& ciphertexts);
    // void generate_challenge(const Player& P);
    void set_bound(const mpz_class& b);
    mpz_class get_bound() const;
    // bool check_bounds(modp& sx) const;

};
#endif