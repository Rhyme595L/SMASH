#include "Commit_prover.h"

CommitProver::CommitProver(CommProof& proof) {
    r1.resize(proof.n_proofs);
    r2.resize(proof.n_proofs);
}


size_t CommitProver::NIZKPoK(CommProof& P, std::stringstream& ciphertexts, 
    std::stringstream& cleartexts,
    const ELGL_PK& pk,
    const vector<BLS12381Element>& g1,
    const vector<Ciphertext>& c,
    const vector<BLS12381Element>& y3,
    const vector<Plaintext>& x,
    const CommProof::Randomness& r){
    // size_t allocate = (8 * c.size() + 2) * sizeof(c[0]);
    // ciphertexts.resize_precise(allocate);
    // ciphertexts.reset_write_head();


    for (unsigned int i = 0; i < c.size(); i++){
        g1[i].pack(ciphertexts);
        c[i].pack(ciphertexts);
        y3[i].pack(ciphertexts);
    }
    
    // int V = P.n_proofs;

    // PRNG G;
    // G.ReSeed();

    // ciphertexts.store(V);

    BLS12381Element c_0, c_1, c_2, tmp_;

    for (int i = 0; i < P.n_proofs; i++) {
        
        r1[i].set_random();
        r2[i].set_random();

        // g^r1 = t1
        c_0 = BLS12381Element(r1[i].get_message());
        c_0.pack(ciphertexts);

        // c_1 = g^r2 * h^r1
        tmp_ = pk.get_pk() * r1[i].get_message();
        
        c_1 = BLS12381Element(r2[i].get_message());
        c_1 += tmp_;
        c_1.pack(ciphertexts);

        // c_2 = g1^r2 * h^r1
        c_2 = g1[i] * r2[i].get_message();
        c_2 += tmp_;
        c_2.pack(ciphertexts);
    }

    P.set_challenge(ciphertexts);

    // size_t allocate2 = (P.n_proofs * 3 + 5) * sizeof(x[0]);
    // cleartexts.resize_precise(allocate2);
    // cleartexts.reset_write_head();

    // cleartexts.store(P.n_proofs);

    Plaintext sx, sr;

    for(int i = 0; i < P.n_proofs; i++){
        sx = x[i] * P.challenge;
        sx += r2[i];
        sx.pack(cleartexts);
        sr = r[i] * P.challenge;
        sr += r1[i];
        sr.pack(cleartexts);
    }

    return report_size();
}

size_t CommitProver::report_size(){
    size_t res = 0;
    res += sizeof(r1);
    res += sizeof(r2);
    res *= r1.size();
    return res;
}

// void CommitProver::report_size(MemoryUsage& res)
// {
//   res.update("prover r1", r1.size());
//   res.update("prover r2", r2.size());
// }

