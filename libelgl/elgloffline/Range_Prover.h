#ifndef RANGE_PROVER_H
#define RANGE_PROVER_H

#include "Range_Proof.h"
#include "libelgl/elgl/Ciphertext.h"
#include "emp-aby/utils.h"

class RangeProver{
    std::vector <Plaintext> r1, r2;
    public:

    RangeProver(RangeProof& proof);
    
    size_t NIZKPoK(RangeProof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts, const ELGL_PK& pk, const std::vector<BLS12381Element>& g1, 
        const std::vector<BLS12381Element>& y3, const std::vector<BLS12381Element>& y2, const std::vector<Plaintext>& x, const Plaintext& ski, ThreadPool* pool);

    size_t report_size();

    // void report_size(MemoryUsage& res);

    // void report_size(ReportType type, MemoryUsage& res);
};

#endif