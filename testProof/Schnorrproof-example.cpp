#include "libelgl/elgloffline/Schnorr_Proof.h"
#include "libelgl/elgloffline/Schnorr_Prover.h"
#include "libelgl/elgloffline/Schnorr_Verifier.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"
#include <chrono>
using namespace std;

int main(){
    BLS12381Element::init();
    ELGL_KeyPair keypair;
    keypair.generate();
    ELGL_PK pk = keypair.get_pk();
    size_t n_tilde = 65536;
    Schnorr_Proof proof(pk, n_tilde);

    vector<Plaintext> x;
    vector<BLS12381Element> c;
    x.resize(n_tilde);
    c.resize(n_tilde);
    for(size_t i = 0; i < n_tilde; i++){
        x[i].set_random();
        c[i] = BLS12381Element(1) * x[i].get_message();
    }

    std::cout << "finish x,c gen" << std::endl;

    std::cout << "prove start" << std::endl;

    Schnorr_Prover prover(proof);
    stringstream ciphertexts, cleartexts;
    // time
    auto start = std::chrono::high_resolution_clock::now();
    prover.NIZKPoK(proof, ciphertexts, cleartexts, c, x);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Time taken for prover.NIZKPoK: " << elapsed.count() << " seconds" << std::endl;
    std::cout << "prove finish" << std::endl;

    std::cout << "verify start" << std::endl;
    Schnorr_Verifier verifier(proof);
    // time
    start = std::chrono::high_resolution_clock::now();
    verifier.NIZKPoK(c, ciphertexts, cleartexts);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed2 = end - start;
    std::cout << "Time taken for verifier.NIZKPoK: " << elapsed2.count() << " seconds" << std::endl;

}