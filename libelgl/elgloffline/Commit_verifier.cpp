#include "Commit_verifier.h"

CommitVerifier::CommitVerifier(CommProof& proof) :
    P(proof)
{
    sx.resize(proof.n_proofs);
    sr.resize(proof.n_proofs);
}

void CommitVerifier::NIZKPoK(vector<Ciphertext>& c,vector<BLS12381Element>& y3, std::stringstream& ciphertexts, std::stringstream& cleartexts, vector<BLS12381Element>& g1, const ELGL_PK& pk){
    P.set_challenge(ciphertexts);

    // bigint bound;
    // bound.unpack(cleartexts);

    for (int i = 0; i < P.n_proofs; i++){
        // remember initial
        g1[i].unpack(ciphertexts);
        c[i].unpack(ciphertexts);
        y3[i].unpack(ciphertexts);
    }

    // ciphertexts.get(V);
    // if (V != P.n_proofs)
    //     throw length_error("number of received commitments incorrect");

    BLS12381Element t1, t2, t3;
    
    Plaintext sx_tmp;
    Plaintext sr_tmp;

    BLS12381Element gsr, hsr, gsxhsr;

    BLS12381Element y_1_tmp, y_2_tmp;
    BLS12381Element t1y1lamda, t2y2lamda;
    BLS12381Element g1sxhsr;      

    BLS12381Element t3y3lambda;
    for (int i = 0; i < P.n_proofs; i++){
        sx_tmp.unpack(cleartexts);
        sr_tmp.unpack(cleartexts);

        t1.unpack(ciphertexts);
        t2.unpack(ciphertexts);
        t3.unpack(ciphertexts);
        
        // g^sr 1 eq left
        gsr = BLS12381Element(sr_tmp.get_message());
        hsr = pk.get_pk() * sr_tmp.get_message();
        
        // g^sx * h^sr 2 eq left
        gsxhsr = BLS12381Element(sx_tmp.get_message());
        gsxhsr += hsr;

        // t1 * y1^lambda 1 eq right 
        t1y1lamda = c[i].get_c0() * P.challenge.get_message();
        t1y1lamda += t1;

        // t2 * y2^lambda 2 eq right
        t2y2lamda = c[i].get_c1() * P.challenge.get_message();
        t2y2lamda += t2;

        // g^sx * g1^sr 3 eq left
        
        g1sxhsr = g1[i] * sx_tmp.get_message();
        g1sxhsr += hsr;

        // t3 * y3^lambda 3 eq right

        t3y3lambda = y3[i] * P.challenge.get_message();
        t3y3lambda += t3;

        if (gsr != t1y1lamda || gsxhsr != t2y2lamda || g1sxhsr != t3y3lambda ){
            throw runtime_error("invalid proof");
        }
    }
    cout << "valid proof" << endl;
}