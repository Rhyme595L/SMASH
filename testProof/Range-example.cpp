#include "libelgl/elgloffline/Range_Prover.h"
#include "libelgl/elgloffline/Range_Verifier.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"
#include "emp-aby/io/multi-io.hpp"
#include <chrono>

using namespace std;

const int threads = 4;
int main(){

    BLS12381Element::init();
    ELGL_KeyPair key;
    key.generate();

    ThreadPool pool(threads);
    
    RangeProof proof(key.get_pk(), 2, 2);
    Plaintext r;
    r.set_random();
    ELGL_PK pk = key.get_pk();
    // calculate y1 y3
    vector<Plaintext> x;
    BLS12381Element y1;
    vector<BLS12381Element> y2, y3;
    vector<BLS12381Element> g1;
    x.resize(proof.n_proofs);
    g1.resize(proof.n_proofs);
    y2.resize(proof.n_proofs);
    y3.resize(proof.n_proofs);
    y1 = BLS12381Element(r.get_message());

    for(size_t i = 0; i < proof.n_proofs; i++){
        x[i].set_random(proof.bound);
        g1[i] = BLS12381Element(x[i].get_message());
        y2[i] = BLS12381Element(x[i].get_message()) + g1[i] * r.get_message();
        y3[i] = BLS12381Element(x[i].get_message()) + pk.get_pk() * r.get_message();
    }

    RangeProver prover(proof);
    std::stringstream ciphertexts, cleartexts;
    std::cout << "prove start" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    prover.NIZKPoK(proof, ciphertexts, cleartexts, pk, g1, y3, y2, x, r, &pool);

    auto end = std::chrono::high_resolution_clock::now(); 
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;
    std::cout << "prove end" << std::endl;
    // verifier

    RangeVerifier verifier(proof);
    std::cout << "verify start" << std::endl;
    auto start2 = std::chrono::high_resolution_clock::now();
    verifier.NIZKPoK(y1, y3, y2, ciphertexts, cleartexts, g1, pk, &pool);
    auto end2 = std::chrono::high_resolution_clock::now(); 
    std::chrono::duration<double, std::milli> duration2 = end2 - start2;
    std::cout << "verify end. Time: " << duration2.count() << " ms" << std::endl;
    std::cout << "verify end" << std::endl;
    return 0;
}