#include "Exp_prover.h"
#include <future>
ExpProver::ExpProver(ExpProof& proof) {
    k.resize(proof.n_proofs);
}

struct thread1Ret
{
    BLS12381Element v;
};

struct thread2Ret
{
    Plaintext s;
};
// not parallel yet
// size_t ExpProver::NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts,
//                const vector<BLS12381Element>& g1,
//                const vector<BLS12381Element>& y1,
//                const vector<BLS12381Element>& y2,
//                const vector<Plaintext>& x){
//                 // TODO: check if allocate is enough


//     Plaintext z;

//     for (unsigned int i = 0; i < y1.size(); i++){
//         g1[i].pack(ciphertexts);
//         y1[i].pack(ciphertexts);
//         y2[i].pack(ciphertexts);
//     }
//     // z = H(g1,y1,y2)

//     z.setHashof(ciphertexts.str().c_str(), ciphertexts.str().size()); 


//     BLS12381Element v;

//     // v = (g^z * g1)^k, z = H(y1,y2)
//     for (int i = 0; i < P.n_proofs; i++) {
        
//         k[i].set_random();
//         v = BLS12381Element(z.get_message()) + g1[i];
//         v = v * k[i].get_message();
//         v.pack(ciphertexts);
//     }

//     P.set_challenge(ciphertexts);



//     Plaintext s;

//     // s = k - x * challenge
//     for (int i = 0; i < P.n_proofs; i++){
//         s = k[i];
//         s -= x[i] * P.challenge;
//         s.pack(cleartexts);
//     }
//     return report_size();
// }

// Decproof 中使用的
size_t ExpProver::NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts,
    const BLS12381Element& g1,
    const vector<BLS12381Element>& y1,
    const vector<BLS12381Element>& y2,
    const vector<Plaintext>& x, ThreadPool* pool){
     // TODO: check if allocate is enough


    Plaintext z;
    g1.pack(ciphertexts);
    for (unsigned int i = 0; i < y1.size(); i++){
        y1[i].pack(ciphertexts);
        y2[i].pack(ciphertexts);
    }
    // z = H(g1,y1,y2)

    z.setHashof(ciphertexts.str().c_str(), ciphertexts.str().size()); 
    // int V = P.n_proofs;

    std::vector<std::future<thread1Ret>> futures1;
    // v = (g^z * g1)^k, z = H(y1,y2)
    for (int i = 0; i < P.n_proofs; i++) {
        futures1.emplace_back(pool->enqueue([this, &g1, &z, i]() -> thread1Ret {
            BLS12381Element v;
            this->k[i].set_random();
            v = BLS12381Element(z.get_message()) + g1;
            v = v * k[i].get_message();
            return {v};
        }));
    }

    for (auto& f : futures1) {
        thread1Ret result = f.get();
        result.v.pack(ciphertexts);
    }

    P.set_challenge(ciphertexts);


    std::vector<std::future<thread2Ret>> futures2;
    // s = k - x * challenge
    for (int i = 0; i < P.n_proofs; i++){
        futures2.emplace_back(pool->enqueue([this, &x, &P, i]() -> thread2Ret {
            Plaintext s;
            s = this->k[i];
            s -= x[i] * P.challenge;
            return {s};
        }));
    }

    for (auto & f : futures2) {
        thread2Ret result = f.get();
        result.s.pack(cleartexts);
    }
    futures1.clear();
    futures2.clear();
    return report_size();
}

// Online 
size_t ExpProver::NIZKPoK(ExpProof& P, std::stringstream& ciphertexts, std::stringstream&  cleartexts,
    const BLS12381Element& g1,
    const BLS12381Element& y1,
    const BLS12381Element& y2,
    const Plaintext& x, int i, ThreadPool* pool){
    std::future<size_t> future = pool->enqueue([&, i]() -> size_t {
        // Step 1: 先为 hash 创建 buffer
        std::stringstream hashbuf;
        BLS12381Element yy2 = y2;
        yy2.pack(hashbuf);  // only include y2 for hash
        std::string hash_input = hashbuf.str();

        // Step 2: compute z
        Plaintext z;
        z.setHashof(hash_input.c_str(), hash_input.size()); 

        // Step 3: write into actual transmission ciphertexts
        this->k[0].set_random();
        yy2.pack(ciphertexts);  // now write y2 into ciphertexts
        BLS12381Element v = BLS12381Element(z.get_message()) + g1;
        v = v * k[0].get_message();
        v.pack(ciphertexts);    // v goes after y2

        P.set_challenge(ciphertexts);
        Fr challenge = P.challenge.get_message();

        Plaintext s;
        s = this->k[0];
        s -= x * P.challenge;
        s.pack(cleartexts);
        // // if (i == 1){
        //     std::cout << "***************** " << i << " *****************" << endl << "P.challenge: " << challenge.getStr() << std::endl;
        // // }
        // std::cout << "***************** " << i << " *****************" << endl << "y2: " << yy2.getPoint().getStr() << std::endl;
        // std::cout << "***************** " << i << " *****************" << endl << "z: " << z.get_message() << std::endl;
        // std::cout << "***************** " << i << " *****************" << endl << "v: " << v.getPoint().getStr() << std::endl;
        // std::cout << "***************** " << i << " *****************" << endl << "s: " << s.get_message() << std::endl;

        return report_size();
    });
    return future.get();
}

size_t ExpProver::report_size(){
    size_t res = 0;
    res += sizeof(k);
    res *= k.size();
    return res;
}

// void ExpProver::report_size(MemoryUsage& res)
// {
//   res.update("prover k", k.size());
// }