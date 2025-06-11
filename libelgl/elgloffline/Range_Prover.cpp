#include "Range_Prover.h"
#include <future>

RangeProver::RangeProver(RangeProof& proof) {
    r1.resize(proof.n_proofs);
    r2.resize(proof.n_proofs);
}

struct thread_return1 {
    BLS12381Element t1;
    BLS12381Element t2;
    BLS12381Element t3;
    Plaintext rr1;
    Plaintext rr2;
};

struct thread_return2 {
    Plaintext sr;
    Plaintext sx;
};


size_t RangeProver::NIZKPoK(RangeProof& P,
    std::stringstream& ciphertexts,
    std::stringstream& cleartexts,
    const ELGL_PK& pk,
    const std::vector<BLS12381Element>& g1,
    const std::vector<BLS12381Element>& y3,
    const std::vector<BLS12381Element>& y2,
    const std::vector<Plaintext>& x,
    const Plaintext& ski, ThreadPool* pool) {
    // TODO: check if allocate is enough

    for (unsigned int i = 0; i < y3.size(); ++i) {
        y2[i].pack(ciphertexts);
        y3[i].pack(ciphertexts);
    }




    std::vector<std::future<thread_return1>> futures1;
    futures1.reserve(P.n_proofs);
    for (int i = 0; i < P.n_proofs; i++) {
        // r1[i].set_random();
        // r2[i].set_random();
        futures1.emplace_back(pool->enqueue([this, &pk, &g1, i]() -> thread_return1 {
            Plaintext rr1, rr2;
            rr1.set_random();
            rr2.set_random();
            BLS12381Element c_0, c_1, c_2, c_3;
            c_0 = BLS12381Element(rr1.get_message());

            // t3 = pk^r1 * g^r2
            c_1 = pk.get_pk() * rr1.get_message();
    
            c_2 = BLS12381Element(rr2.get_message());
    
            c_1 += c_2;
    
            // t2 = g1^r1 * g^r2
            c_2 = g1[i] * rr1.get_message(); 
            c_3 = BLS12381Element(rr2.get_message());
            c_2 += c_3;
            return {c_0, c_1, c_2, rr1, rr2};
        }));
    }

    for (size_t i = 0; i < P.n_proofs; i++)
    {
        thread_return1 result = futures1[i].get();
        result.t1.pack(ciphertexts);
        result.t3.pack(ciphertexts);
        result.t2.pack(ciphertexts);
        r1[i] = result.rr1;
        r2[i] = result.rr2;
    }
    futures1.clear();

    P.set_challenge(ciphertexts);


    // cleartexts.store(P.n_proofs);
    // // print n_proofs
    // std::cout << "prover n_proofs: " << P.n_proofs << std::endl;

    
    std::vector<std::future<thread_return2>> futures2;
    futures2.reserve(P.n_proofs);
    for (int i = 0; i < P.n_proofs; i++){
        futures2.emplace_back(pool->enqueue([&, i]() -> thread_return2 {
            Plaintext sx, sr;
            sx = P.challenge * x[i];
        sx += r2[i];

        sr = P.challenge * ski;
        sr += r1[i];
       return {sr, sx};
    }));
    }
    for (size_t i = 0; i < P.n_proofs; i++)
    {
        thread_return2 result = futures2[i].get();
        result.sx.pack(cleartexts);
        result.sr.pack(cleartexts);
    }
    futures2.clear();
    return report_size();
}

size_t RangeProver::report_size(){
    size_t res = 0;
    res += r1.size() * sizeof(r1[0]);
    return res;
}


