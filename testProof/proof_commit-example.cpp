#include "libelgl/elgloffline/Commit_proof.h"
#include "libelgl/elgloffline/Commit_prover.h"
#include "libelgl/elgloffline/Commit_verifier.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"

using namespace std;
int main(){

    BLS12381Element::init();
    ELGL_KeyPair keypair;
    keypair.generate();
    ELGL_PK pk = keypair.get_pk();
    size_t n_tilde = 65536;
    CommProof proof(pk, n_tilde);

    CommitProver prover(proof);
    proof.n_proofs = n_tilde;

    stringstream ciphertexts;
    stringstream cleartexts;
    vector<BLS12381Element> g1;
    vector<Plaintext> x;
    CommProof::Randomness r;
    // c = (g^r, g^x * h^r) = (y1, y2)
    vector<Ciphertext> c;
    // y3 = g_1^x * h^r
    vector<BLS12381Element> y3;

    x.resize(n_tilde);
    r.resize(n_tilde);
    c.resize(n_tilde);
    y3.resize(n_tilde);
    g1.resize(n_tilde);

    Plaintext tmp;
    for(size_t i = 0; i < n_tilde; i++){
        x[i].set_random();
        r[i].set_random();
        tmp.set_random();
        g1[i] = BLS12381Element(tmp.get_message());
        // y1, y2
        // c = (g^r, g^x * h^r) = (y1, y2)
        c[i] = Ciphertext(BLS12381Element(r[i].get_message()), BLS12381Element(x[i].get_message()) + pk.get_pk() * r[i].get_message());
        // y3 = g_1^x * h^r
        y3[i] = g1[i] * x[i].get_message() + pk.get_pk() * r[i].get_message();
    }
    cout << "finish statement gen" << endl;

    // size_t NIZKPoK(CommProof& P, octetStream& ciphertexts, octetStream& cleartexts, const ELGL_PK& pk, const BLS12381Element& g1, const vector<Ciphertext>& c, const vector<BLS12381Element>& y3, const vector<Plaintext>& x, const CommProof::Randomness& r);
    cout << "start proof" << endl;
    prover.NIZKPoK(proof, ciphertexts, cleartexts, pk, g1, c, y3, x, r);
    cout << "end proof" << endl;

    CommitVerifier verifier(proof);

    // void CommitVerifier::NIZKPoK(vector<Ciphertext>& c,vector<BLS12381Element>& y3, octetStream& ciphertexts, octetStream& cleartexts, const BLS12381Element& g1, const ELGL_PK& pk)
    cout << "start verify" << endl;
    verifier.NIZKPoK(c, y3, ciphertexts, cleartexts, g1, pk);
    cout << "end verify" << endl;
}