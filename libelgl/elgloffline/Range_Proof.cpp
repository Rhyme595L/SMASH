#include "Range_Proof.h"

void RangeProof::set_challenge(const std::stringstream& ciphertexts) {
    auto* buf = ciphertexts.rdbuf();
    std::streampos size = buf->pubseekoff(0,ciphertexts.end, ciphertexts.in);
    buf->pubseekpos(0, ciphertexts.in);
    char* tmp = new char[size];
    buf->sgetn(tmp, size);
    challenge.setHashof(tmp, size);
    delete [] tmp;
}

// void RangeProof::generate_challenge(const Player &P)
// {
//   GlobalPRNG G(P);
// //   set_challenge(G);
// }

void RangeProof::set_bound(const mpz_class& b){
    bound = b;
}


mpz_class RangeProof::get_bound() const{
    return bound;
}