#include "ZKP_Enc_Prover.h"
#include <future>

EncProver::EncProver(Proof& proof)
{
    r1.resize(proof.n_proofs);
    r2.resize(proof.n_proofs);
}

struct thread1Ret {
    BLS12381Element c0;
    BLS12381Element c1;
};

struct thread2Ret {
    Plaintext sx;
    Plaintext sr;
};

void EncProver::NIZKPoK(Proof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts, const ELGL_PK& pk, const std::vector<Ciphertext>& c, const std::vector<Plaintext>& x, const Proof::Random_C& r, ThreadPool * pool) {

    for (unsigned int i = 0; i < c.size(); i++){
      c[i].pack(ciphertexts);
    }

    int V = P.n_proofs;

    // PRNG G;
    // G.ReSeed();
    
    // ciphertexts.store(V);
    std::vector<std::future<thread1Ret>> futures1;
    // r1: vector of r_1, r2: vector of r_2
    for (int i = 0; i < V; i++) {
        futures1.emplace_back(pool->enqueue([this, &pk, i, &r]() -> thread1Ret {
            BLS12381Element c_0, c_1, c_2;
            r1[i].set_random();
            r2[i].set_random();
  
          c_0 = BLS12381Element(r1[i].get_message());
  
          c_1 = pk.get_pk() * r1[i].get_message();
  
          c_2 = BLS12381Element(r2[i].get_message());
  
          // Mul(c_1, c_1, c_2, pk.get_params().get_plaintext_field_data().get_prD());
          c_1 = c_1 + c_2;
          return {c_0, c_1};              
        }));
    }

    for(auto& f : futures1) {
        auto ret = f.get();
        ret.c0.pack(ciphertexts);
        ret.c1.pack(ciphertexts);
    }

    // Challenge
    P.set_challenge(ciphertexts);

    // cleartexts.store(P.n_proofs);

    std::vector<std::future<thread2Ret>> futures2;

    for (int i = 0; i < P.n_proofs; i++) {
      futures2.emplace_back(pool->enqueue([this, &pk, i, &P, &x, &r]() -> thread2Ret {
            Plaintext sx, sr;
            sx = P.challenge * x[i];
            sx += r2[i];
            sr = P.challenge * r[i];
            sr += r1[i];
            return {sx, sr};
        }));
    }
    for (auto & f : futures2) {
        thread2Ret result = f.get();
        result.sx.pack(cleartexts);
        result.sr.pack(cleartexts);
    }
//   return report_size();
}