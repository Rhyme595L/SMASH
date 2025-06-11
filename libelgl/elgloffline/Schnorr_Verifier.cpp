#include "Schnorr_Verifier.h"

#include <future>
Schnorr_Verifier::Schnorr_Verifier(Schnorr_Proof& proof) :
    P(proof)
{
    // rd.resize(proof.n_tilde);
}



void Schnorr_Verifier::NIZKPoK(std::vector<BLS12381Element>& c, std::stringstream& ciphertexts, std::stringstream& cleartexts, ThreadPool * pool) {
    // int V;
    std::vector<BLS12381Element> R;
    R.resize(P.n_tilde);
    P.set_challenge(ciphertexts);
    for (size_t i = 0; i < P.n_tilde; i++){
        // c = g^x 
        c[i].unpack(ciphertexts);
    }
    
    // cleartexts.get(V);
    // if (V != P.n_tilde)
    //     throw length_error("number of received commitments incorrect");
    std::vector<Plaintext> z;
    z.resize(P.n_tilde);
    for (size_t i = 0; i < P.n_tilde; i++){
        R[i].unpack(ciphertexts);
        z[i].unpack(cleartexts);
    }


    

    std::vector<std::future<void>> futures;
    // check g^z = R * c^challenge
    for (size_t i = 0; i < P.n_tilde; i++){
        futures.emplace_back(pool->enqueue([this, i, &c, &R, &z]() -> void {
            BLS12381Element Left, Right;
            Right = c[i] * P.challenge.get_message();
            Right += R[i];
    
            Left = BLS12381Element(z[i].get_message());
    
            if (Left != Right){
                throw std::runtime_error("invalid proof");
            }
    
        }));
    }
    for (auto& f : futures) {
        f.get();
    }
    std::cout << "valid proof" << std::endl;
}