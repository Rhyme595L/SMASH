#ifndef EXP_PROVER_H
#define EXP_PROVER_H

#include "Exp_proof.h"
#include "libelgl/elgl/Ciphertext.h"
#include "emp-aby/utils.h"

class ExpProver{
    vector <Plaintext> k;
    public:

    ExpProver(ExpProof& proof);
    
    // size_t NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts, const vector<BLS12381Element>& g1, const vector<BLS12381Element>& y1, const vector<BLS12381Element>& y2, const vector<Plaintext>& x);

    size_t NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts,
        const BLS12381Element& g1,
        const vector<BLS12381Element>& y1,
        const vector<BLS12381Element>& y2,
        const vector<Plaintext>& x, ThreadPool* pool);

    size_t NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts,
        const BLS12381Element& g1,
        const BLS12381Element& y1,
        const BLS12381Element& y2,
        const Plaintext& x, int i, ThreadPool* pool);
    
    size_t report_size();

    // void report_size(MemoryUsage& res);

    // void report_size(ReportType type, MemoryUsage& res);
};

#endif