#include "libelgl/elgloffline/RotationProof.h"
#include "libelgl/elgloffline/RotationProver.h"
#include "libelgl/elgloffline/RotationVerifier.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"
#include <chrono>
#include <string>
#include <sstream>
#include <vector>

using namespace std;
const int threads = 4;

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(const std::string &in) {
    std::string out;
    int val=0, valb=-6;
    for (unsigned char c : in) {
        val = (val<<8) + c;
        valb += 8;
        while (valb>=0) {
            out.push_back(base64_chars[(val>>valb)&0x3F]);
            valb-=6;
        }
    }
    if (valb>-6) out.push_back(base64_chars[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string &in) {
    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T[base64_chars[i]] = i;
    std::string out;
    int val=0, valb=-8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            out.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}

int main(){

    BLS12381Element::init();
    ELGL_KeyPair keypair;
    keypair.generate();
    ELGL_PK pk = keypair.get_pk();
    size_t n_tilde = 2;

    ThreadPool pool(threads);

    RotationProof proof(pk, pk, n_tilde);
    vector<BLS12381Element> ax, bx, dx, ex;
    ax.resize(n_tilde);
    bx.resize(n_tilde);
    dx.resize(n_tilde);
    ex.resize(n_tilde);

    Plaintext exp, alpha, beta;
    exp.set_random();
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << 1;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    Plaintext::pow(beta, alpha, exp);
    std::cout << "finish beta gen" << std::endl;

    Plaintext a;
    for (size_t i = 0; i < proof.n_tilde; i++){
        a.set_random();
        ax[i] = BLS12381Element(a.get_message());
        a.set_random();
        bx[i] = BLS12381Element(a.get_message());
    }

    std::cout << "finish ax bx gen" << std::endl;

    vector<Plaintext> sk_k;
    sk_k.resize(n_tilde);
    for (size_t i = 0; i < proof.n_tilde; i++){
        sk_k[i].set_random();
    }
    std::cout << "finish sk_k gen" << std::endl;
    //  calculate beta

    vector <Plaintext> betak;
    betak.resize(n_tilde);

    for (size_t i = 0; i < proof.n_tilde; i++){
        // calculate beta^k
        if (i == 0) {betak[i].assign(1);}
        else {betak[i] = betak[i - 1] * beta;}
        dx[i] = BLS12381Element(1) * sk_k[i].get_message();
        dx[i] += ax[i] * betak[i].get_message();
        // e_k = bk ^ betak * h^sk
        ex[i] = pk.get_pk() * sk_k[i].get_message();
        ex[i] += bx[i] * betak[i].get_message();
    }
    std::cout << "finish dk ek gen" << std::endl;
    
    // 增加时间测试prove时长
    std::cout << "prove start" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    RotationProver prover(proof);
    stringstream ciphertexts, cleartexts;

    std::cout << std::endl;
    prover.NIZKPoK(proof, ciphertexts, cleartexts, pk, pk, dx, ex, ax, bx, beta, sk_k, &pool);
    auto end = std::chrono::high_resolution_clock::now(); 
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;
    std::cout << "prove end" << std::endl;

    string comm_raw, response_raw;
    comm_raw = ciphertexts.str();
    response_raw = cleartexts.str();
    std::stringstream comm_, response_;
    comm_ << base64_encode(comm_raw);
    response_ << base64_encode(response_raw);

    std::stringstream comm_ro, response_ro;
    std::string comm_raw_final, response_raw_final;
    comm_raw_final = comm_.str();
    response_raw_final = response_.str();
    comm_ro << base64_decode(comm_raw_final);
    response_ro << base64_decode(response_raw_final);
    // verifier
    std::cout << "verify start" << std::endl;
    auto start2 = std::chrono::high_resolution_clock::now();
    RotationVerifier verifier(proof);
    verifier.NIZKPoK(dx, ex, ax, bx, comm_ro, response_ro, pk, pk, &pool);

    std::cout << std::endl;
    auto end2 = std::chrono::high_resolution_clock::now(); 
    std::chrono::duration<double, std::milli> duration2 = end2 - start2;
    std::cout << "verify end. Time: " << duration2.count() << " ms" << std::endl;
    std::cout << "verify end" << std::endl;
}