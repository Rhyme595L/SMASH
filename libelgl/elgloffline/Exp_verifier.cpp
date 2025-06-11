#include "Exp_verifier.h"
#include <future>
ExpVerifier::ExpVerifier(ExpProof& proof) :
    P(proof)
{
    s.resize(proof.n_proofs);
}


// void ExpVerifier::NIZKPoK(vector<BLS12381Element>& g1, vector<BLS12381Element>& y1,vector<BLS12381Element>& y2, std::stringstream& ciphertexts, std::stringstream&  cleartexts){
//     P.set_challenge(ciphertexts);

//     // bigint bound;
//     // bound.unpack(cleartexts);
//     Plaintext z;
//     std::stringstream buf;
//     // z = H(g1,y1,y2)
//     for (int i = 0; i < P.n_proofs; i++){
//         // remember initial
//         g1[i].unpack(ciphertexts);
//         g1[i].pack(buf);
//         y1[i].unpack(ciphertexts);
//         y1[i].pack(buf);
//         y2[i].unpack(ciphertexts);
//         y2[i].pack(buf);
//     }

//     z.setHashof(buf.str().c_str(), buf.str().size()); 

//     BLS12381Element t1, t2, t3;
    
//     // v = (g^z * g1)^s * (y1^z * y2)^challenge, 
//     Plaintext s;

//     BLS12381Element v, Right1, Right2;
//     for (int i = 0; i < P.n_proofs; i++){
//         s.unpack(cleartexts);
//         v.unpack(ciphertexts);

//         Right1 = BLS12381Element(z.get_message()) + g1[i];
//         Right1 = Right1 * s.get_message();
        
//         Right2 = y1[i] * z.get_message() + y2[i];
//         Right2 = Right2 * P.challenge.get_message();

//         Right1 += Right2;

//         if (v != Right1 ){
//             throw runtime_error("invalid proof");
//         }
//     }
//     cout << "valid proof" << endl;
// }

void ExpVerifier::NIZKPoK(BLS12381Element& g1, vector<BLS12381Element>& y1,vector<BLS12381Element>& y2, std::stringstream& ciphertexts, std::stringstream& cleartexts, ThreadPool* pool){
    ciphertexts.seekg(0);
    cleartexts.seekg(0);
    P.set_challenge(ciphertexts);
    ciphertexts.seekg(0);
    cleartexts.seekg(0);

    Plaintext z;
    std::stringstream buf;

    g1.unpack(ciphertexts);
    g1.pack(buf);
    for (int i = 0; i < P.n_proofs; i++){
        // remember initial

        y1[i].unpack(ciphertexts);
        y1[i].pack(buf);
        y2[i].unpack(ciphertexts);
        y2[i].pack(buf);
    }

    z.setHashof(buf.str().c_str(), buf.str().size()); 

    BLS12381Element t1, t2, t3;
    
    // v = (g^z * g1)^s * (y1^z * y2)^challenge
    std::vector<Plaintext> s(P.n_proofs);
    std::vector<BLS12381Element> v(P.n_proofs);
    for (int i = 0; i < P.n_proofs; i++){
        s[i].unpack(cleartexts);
        v[i].unpack(ciphertexts);
    }
    vector<std::future<void>> futures;
    for (int i = 0; i < P.n_proofs; i++){
        futures.emplace_back(pool->enqueue([this, &g1, &z, i, &s, &v, &y1, &y2]() {
            BLS12381Element Right1, Right2;
            Right1 = BLS12381Element(z.get_message()) + g1;
            Right1 = Right1 * s[i].get_message();
            Right2 = y1[i] * z.get_message() + y2[i];
            Right2 = Right2 * P.challenge.get_message();

            Right1 += Right2;
            if (v[i] != Right1 ){
                throw runtime_error("invalid exp proof");
            }
        }));
    }
    for (auto& f : futures) {
        f.get();
    }

    // cout << "valid proof" << endl;
}

void ExpVerifier::NIZKPoK(BLS12381Element& g1, BLS12381Element& y1, BLS12381Element& y2, std::stringstream& ciphertexts, std::stringstream& cleartexts, ThreadPool* pool, int i){

    std::future<void> future;
    future = pool->enqueue([&, i]() {

        ciphertexts.seekg(0);
        cleartexts.seekg(0);
        P.set_challenge(ciphertexts);
        ciphertexts.seekg(0);
        cleartexts.seekg(0);
        y2.unpack(ciphertexts);
        Fr challenge = P.challenge.get_message();

        std::stringstream hashbuf;
        y2.pack(hashbuf);  // only include y2 for hash
        std::string hash_input = hashbuf.str();

        // Step 2: compute z
        Plaintext z;
        z.setHashof(hash_input.c_str(), hash_input.size()); 

        BLS12381Element t1, t2, t3;
        
        // v = (g^z * g1)^s * (y1^z * y2)^challenge
        Plaintext s;
        BLS12381Element v;
        
        s.unpack(cleartexts);
        v.unpack(ciphertexts);
        BLS12381Element Right1, Right2;

        Right1 = BLS12381Element(z.get_message()) + g1;
        Right1 = Right1 * s.get_message();
        Right2 = y1 * z.get_message() + y2;
        Right2 = Right2 * P.challenge.get_message();

        Right1 += Right2;
        // if (v != Right1 ){
        //     throw runtime_error("invalid exp proof in ExpVerifier");
        // }
        });
    future.get();

    // cout << "+++++++++ valid proof +++++++++" << endl;
}