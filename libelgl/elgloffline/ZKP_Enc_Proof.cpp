#include "ZKP_Enc_Proof.h"
#include "libelgl/elgl/Ciphertext.h"

void Proof::set_challenge(const std::stringstream& ciphertexts) {
    auto* buf = ciphertexts.rdbuf();
    std::streampos size = buf->pubseekoff(0, ciphertexts.end, ciphertexts.in);
    buf->pubseekpos(0, ciphertexts.in);
    char* tmp = new char[size];
    buf->sgetn(tmp, size);
    challenge.setHashof(tmp, size);
}

// void Proof::set_challenge(PRNG& G){
//     bigint r;
//     r.generateUniform(G, MCL_MAX_FR_BIT_SIZE);
//     challenge.assign(r);
// }

