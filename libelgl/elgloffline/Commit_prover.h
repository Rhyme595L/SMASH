#ifndef COMMIT_PROVER_H
#define COMMIT_PROVER_H

#include "Commit_proof.h"
#include "libelgl/elgl/Ciphertext.h"
#include <vector>
using namespace std;

class CommitProver{
    vector <Plaintext> r1, r2;
    public:

    CommitProver(CommProof& proof);
    
    size_t NIZKPoK(CommProof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts, const ELGL_PK& pk, const vector<BLS12381Element>& g1, const vector<Ciphertext>& c, const vector<BLS12381Element>& y3, const vector<Plaintext>& x, const CommProof::Randomness& r);

    size_t report_size();

    // void report_size(MemoryUsage& res);

    // void report_size(ReportType type, MemoryUsage& res);
};

#endif