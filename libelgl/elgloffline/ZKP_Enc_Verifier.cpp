#include "ZKP_Enc_Verifier.h"
#include <future>

EncVerifier::EncVerifier(Proof& proof) :
    P(proof)
{
    sx.resize(proof.n_proofs);
    sr.resize(proof.n_proofs);
}



void EncVerifier::NIZKPoK(std::vector<Ciphertext>& c, std::stringstream& ciphertexts, std::stringstream& cleartexts,
                const ELGL_PK& pk, ThreadPool * pool) {
    // int V;
    ciphertexts.seekg(0);
    cleartexts.seekg(0);
    
    P.set_challenge(ciphertexts);
    ciphertexts.seekg(0);
    cleartexts.seekg(0);
    for (int i = 0; i < P.n_proofs; i++){
        // remember initial
        c[i].unpack(ciphertexts);
        // convert c_i to bigint

    }

    // t1t2 = (t1, t2), gxr = (g^sr, g^sx h^sr)
    // Ciphertext gxr(pk.get_params());

    std::vector<BLS12381Element> t1(P.n_proofs), t2(P.n_proofs);
    
    // cleartexts.get(V);
    // if (V != P.n_proofs)
    //     throw length_error("number of received commitments incorrect");

    std::vector<Plaintext> sx_tmp(P.n_proofs);
    std::vector<Plaintext> sr_tmp(P.n_proofs);
    


    for (int i = 0; i < P.n_proofs; i++){
        sx_tmp[i].unpack(cleartexts);
        sr_tmp[i].unpack(cleartexts);
        // print sx sr
        // t1t2 = (t1, t2)
        t1[i].unpack(ciphertexts);
        t2[i].unpack(ciphertexts);
        // convert sx to bigint
    }

    std::vector<std::future<void>> futures;
    
    for(int i = 0; i < P.n_proofs; i++){
        futures.emplace_back(pool->enqueue([this, &pk, i, &c, &sx_tmp, &sr_tmp, &t1, &t2]() -> void {
            BLS12381Element gsr, tmp, gsxhsr;

            BLS12381Element y_1_tmp, y_2_tmp;
            BLS12381Element t1y1lamda, t2y2lamda;

            gsr = BLS12381Element(sr_tmp[i].get_message());


            gsxhsr = BLS12381Element(sx_tmp[i].get_message());
    
            tmp = pk.get_pk() * sr_tmp[i].get_message();
    
            gsxhsr = tmp + gsxhsr;
    
            y_1_tmp = c[i].get_c0() * P.challenge.get_message();
    
            y_2_tmp = c[i].get_c1() * P.challenge.get_message();
    
            // Mul(t1y1lamda, t1t2.get_c0(), y_1_tmp, pk.get_params().get_plaintext_field_data().get_prD());
            t1y1lamda = t1[i] + y_1_tmp;
    
            // Mul(t2y2lamda, t1t2.get_c1(), y_2_tmp, pk.get_params().get_plaintext_field_data().get_prD());
            t2y2lamda = t2[i] + y_2_tmp;
    
            if (gsr != t1y1lamda || gsxhsr != t2y2lamda){
                throw std::runtime_error("invalid proof");
            }
        }));
    }

    for(auto & f : futures) {
        f.get();
    }

    // std::cout << "valid proof" << std::endl;
}