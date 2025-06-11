#include "Schnorr_Proof.h"


void Schnorr_Proof::set_challenge(const std::stringstream& ciphertexts) {
  auto* buf = ciphertexts.rdbuf();
  std::streampos size = buf->pubseekoff(0, std::ios_base::cur, std::ios_base::in);
  buf->pubseekpos(0, std::ios_base::in);
  char *tmp = new char[size];
  buf->sgetn(tmp, size);
  challenge.setHashof(tmp, size);
}

// void Schnorr_Proof::set_challenge(PRNG& G){
//     bigint r;
//     r.generateUniform(G, MCL_MAX_FR_BIT_SIZE);
//     challenge.assign(r);
// }

// void Schnorr_Proof::generate_challenge(const Player &P)
// {
//   GlobalPRNG G(P);
//   set_challenge(G);
// }
