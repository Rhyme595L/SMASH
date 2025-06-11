#ifndef COMM_VERIFIER_H
#define COMM_VERIFIER_H

#include "Commit_proof.h"

class CommitVerifier{
    vector<Plaintext> sx, sr;
    CommProof &P;
    public:
    CommitVerifier(CommProof& proof);

    void NIZKPoK(vector<Ciphertext>& c,vector<BLS12381Element>& y2, std::stringstream& ciphertexts, std::stringstream& cleartexts, vector<BLS12381Element>& g1, const ELGL_PK& pk);

    size_t report_size(){return 0;};

};
#endif