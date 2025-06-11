#include "libelgl/elgloffline/Commit_proof.h"
void CommProof::set_challenge(std::stringstream& ciphertexts) {
  // emp::Hash hash;
  auto* buf = ciphertexts.rdbuf();
  std::streampos size = buf->pubseekoff(0, ciphertexts.end, ciphertexts.in);
  buf->pubseekpos(0, ciphertexts.in);
  char* tmp = new char[size];
  buf->sgetn(tmp, size);
  challenge.setHashof(tmp, size);
}

// void CommProof::set_challenge(PRNG& G) {
//     bigint r;
//     r.generateUniform(G, MCL_MAX_FR_BIT_SIZE);
//     challenge.assign(r);
// }