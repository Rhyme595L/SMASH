#include "libelgl/elgloffline/ZKP_Enc_Prover.h"
#include "libelgl/elgloffline/ZKP_Enc_Verifier.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"

using namespace std;
int main(){
    BLS12381Element::init();
    ELGL_KeyPair keypair;
    keypair.generate();
    Plaintext m;
    m.set_random();

    ELGL_PK::Random_C r;
    r.setByCSPRNG();
    ELGL_PK pk = keypair.get_pk();
    std::map<Fp, Fr> P_to_m;

    Ciphertext c = pk.encrypt(m, r);

    Proof proof(pk);

    EncProver prover(proof);

    stringstream ciphertexts, cleartexts;
    Proof::Random_C rand;
    rand.resize(proof.n_proofs);
    rand[0] = r;
    vector<Ciphertext> vc;
    vc.resize(proof.n_proofs, Ciphertext());
    vc[0] = c;
    vector<Plaintext> vp;
    vp.resize(proof.n_proofs, Plaintext());
    vp[0] = m;
    prover.NIZKPoK(proof, ciphertexts, cleartexts, pk, vc, vp, rand);


    EncVerifier verifier(proof);
    verifier.NIZKPoK(vc, ciphertexts, cleartexts, pk);
}