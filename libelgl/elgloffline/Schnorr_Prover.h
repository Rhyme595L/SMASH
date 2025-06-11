#ifndef SCHNORR_PROVER_H
#define SCHNORR_PROVER_H

#include "Schnorr_Proof.h"
#include "libelgl/elgl/Ciphertext.h"

class Schnorr_Prover{
    std::vector <Plaintext> rd;
    public:
    // don't know what this is
    // size_t volatile_memory;

    Schnorr_Prover(Schnorr_Proof& proof);

    size_t NIZKPoK(Schnorr_Proof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts,
               const std::vector<BLS12381Element>& c,
               const std::vector<Plaintext>& x);
    
    size_t report_size();

    // void report_size(MemoryUsage& res);
    };
#endif