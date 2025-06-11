#ifndef RANGE_VERIFIER_H
#define RANGE_VERIFIER_H

#include "Range_Proof.h"
#include "emp-aby/utils.h"

class RangeVerifier{
    RangeProof &P;
    public:
    RangeVerifier(RangeProof& proof);

    void NIZKPoK(const BLS12381Element& y1, std::vector<BLS12381Element>& y3, std::vector<BLS12381Element>& y2, std::stringstream& ciphertexts, std::stringstream& cleartexts, const std::vector<BLS12381Element>& g1,
                const ELGL_PK& pk, ThreadPool* pool);

    // size_t report_size(){return sx.size() * sizeof(modp) + sr.size() * sizeof(modp);};

};
#endif