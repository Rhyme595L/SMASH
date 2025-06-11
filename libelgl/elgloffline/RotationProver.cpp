#include "RotationProver.h"
#include <future>
#include <mutex>



struct PackResult {
    BLS12381Element M_k;
    BLS12381Element CK_inc;
};

RotationProver::RotationProver(RotationProof& proof) {
    mk.resize(proof.n_tilde);
    tk.resize(proof.n_tilde);
    uk.resize(proof.n_tilde);
    vk.resize(proof.n_tilde);
    m_tilde_k.resize(proof.n_tilde);
    yk.resize(proof.n_tilde);
}

size_t RotationProver::NIZKPoK(RotationProof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts, const ELGL_PK& pk, const ELGL_PK& pk_tilde, 
    const std::vector<BLS12381Element> dx, const std::vector<BLS12381Element> ex, const std::vector<BLS12381Element> ax,const std::vector<BLS12381Element> bx, Plaintext& beta, const std::vector<Plaintext>& sk_k, ThreadPool* pool) {
    
    std::mutex C_mutex;

    std::vector<std::future<PackResult>> futures;

    // size_t allocate = (8 * P.n_tilde + 5) * G1::getSerializedByteSize();
    BLS12381Element g = BLS12381Element(1);

    // ciphertexts.resize_precise(allocate);
    // ciphertexts.reset_write_head();
    for (size_t i = 0; i < P.n_tilde; i++)
    {
        ax[i].pack(ciphertexts);
        bx[i].pack(ciphertexts);
        dx[i].pack(ciphertexts);
        ex[i].pack(ciphertexts);
    }

    // std::cout << "finish packing " << std::endl;
    // PRNG G;
    // G.ReSeed();
    // gen m_tilde b

    m_tilde.set_random();
    b.set_random();

    BLS12381Element C_Tilde = pk.get_pk() * m_tilde.get_message();

    std::vector<BLS12381Element> ck(P.n_tilde + 1);
    ck[0] = g;


    std::vector<Plaintext> z(3);
    std::stringstream tmp_pack;
    // for (size_t i = 0; i < 3; i++){
        tmp_pack.str("");
        tmp_pack.clear();
        // mpz(i).pack(tmp_pack);
        tmp_pack << 0;
        ax[0].pack(tmp_pack);
        bx[0].pack(tmp_pack);
        dx[0].pack(tmp_pack);
        ex[0].pack(tmp_pack);
        z[0].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
        z[1].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
        z[2].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
    // }
    
    mk.resize(P.n_tilde);
    tk.resize(P.n_tilde);
    uk.resize(P.n_tilde);
    vk.resize(P.n_tilde);
    m_tilde_k.resize(P.n_tilde);
    yk.resize(P.n_tilde);

    // final
    BLS12381Element M_k;
    BLS12381Element C, CK_tmp;
    C = g;
    Plaintext exp_tmp;
    for (size_t i = 0; i < P.n_tilde; i++)
    {
        tk[i].set_random();
        ck[i+1] = ck[i] * beta.get_message();
        ck[i+1] += pk.get_pk() * tk[i].get_message();
    }
    
    for (size_t i = 0; i < P.n_tilde; ++i) {
        futures.push_back(pool->enqueue([&, i]() -> PackResult {
            std::stringstream tmp_pack;

    
            mk[i].set_random();
            uk[i].set_random();
            vk[i].set_random();
            m_tilde_k[i].set_random();
    
            tmp_pack.str("");
            tmp_pack.clear();
            ax[i].pack(tmp_pack);
            bx[i].pack(tmp_pack);
            dx[i].pack(tmp_pack);
            ex[i].pack(tmp_pack);
            tmp_pack << i;
    
            yk[i].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
    
            PackResult result;
            BLS12381Element CK_tmp = ck[i] * b.get_message();
            CK_tmp += pk.get_pk() * mk[i].get_message();
    
            Fr yki = yk[i].get_message();

            result.CK_inc = CK_tmp * yki;
            Plaintext exp_tmp;
            BLS12381Element M_k;
    
            exp_tmp = z[0] * uk[i] + z[1] * vk[i];
            M_k = g * exp_tmp.get_message();
    
            exp_tmp = z[0] * m_tilde_k[i] + z[2] * vk[i];
            M_k += pk_tilde.get_pk() * exp_tmp.get_message();
    
            exp_tmp = z[1] * uk[i];
            M_k += ax[i] * exp_tmp.get_message();
    
            exp_tmp = z[2] * uk[i];
            M_k += bx[i] * exp_tmp.get_message();
    
            result.M_k = M_k;
    
            return result;
        }));
    }

    for (size_t i = 0; i < futures.size(); ++i) {
        PackResult res = futures[i].get();
        ck[i+1].pack(ciphertexts);
        res.M_k.pack(ciphertexts);
        C += res.CK_inc;
    }
    
    C_Tilde.pack(ciphertexts);

    C = C - g;
    C.pack(ciphertexts);
    // fiat shamir

    P.set_challenge(ciphertexts);

    std::vector<Plaintext> t_star(P.n_tilde + 1);
    std::vector<Plaintext> phi(P.n_tilde), miu(P.n_tilde), niu(P.n_tilde), rou(P.n_tilde);
    Plaintext sigma = P.challenge * beta;
    Plaintext phi_sum(0);
    sigma += b;

    Plaintext betak(1);
    t_star[0].assign_zero();
    // for (size_t i = 0; i < P.n_tilde; i++){
    //     t_star[i+1] = beta * t_star[i];
    //     t_star[i+1] += tk[i];

    //     phi[i] = P.challenge * tk[i];
    //     phi[i] += mk[i];
    //     miu[i] = P.challenge * betak;
    //     betak *= beta;
    //     miu[i] += uk[i];

    //     niu[i] = P.challenge * sk_k[i];
    //     niu[i] += vk[i];

    //     rou[i] = P.challenge * t_star[i];
    //     rou[i] += m_tilde_k[i];
    //     phi_sum += phi[i] * yk[i];
    // }

    // t_star[0].assign_zero();
    for (size_t i = 0; i < P.n_tilde; i++){
        t_star[i+1] = beta * t_star[i];
        t_star[i+1] += tk[i];
        betak *= beta;
    }

    vector<std::future<void>> futures2;
    for (size_t i = 0; i < P.n_tilde; i++){
        futures2.push_back(pool->enqueue([&, i]() {
            Plaintext exp, exp_tmp;
            exp.assign(std::to_string(i));
            Plaintext::pow(exp_tmp, beta, exp);

            phi[i] = P.challenge * tk[i];
            phi[i] += mk[i];
            miu[i] = P.challenge * exp_tmp;
            miu[i] += uk[i];

            niu[i] = P.challenge * sk_k[i];
            niu[i] += vk[i];

            rou[i] = P.challenge * t_star[i];
            rou[i] += m_tilde_k[i];
        }));
    }
    for (auto& f : futures2) {
        f.get();
    }
    futures2.clear();

    for (size_t i = 0; i < P.n_tilde; i++) {
        phi_sum += phi[i] * yk[i];
    }

    Plaintext eta = P.challenge * t_star[P.n_tilde];
    eta += m_tilde;

    // allocate = (3 * P.n_tilde + 3) * Fr::getByteSize();
    // cleartexts.resize_precise(allocate);
    // cleartexts.reset_write_head();


    sigma.pack(cleartexts);
    eta.pack(cleartexts);
    phi_sum.pack(cleartexts);

    for (size_t i = 0; i < P.n_tilde; i++){
        miu[i].pack(cleartexts);
        niu[i].pack(cleartexts);
        rou[i].pack(cleartexts);
    }


    return report_size();
}

size_t RotationProver::report_size(){
    size_t res = 0;
    res += sizeof(m_tilde);
    res += sizeof(b);
    res += mk.size() * sizeof(mk[0]);
    return res;
}

// void RotationProver::report_size(MemoryUsage& res){
//     res.update("prover m_tilde", sizeof(m_tilde));
//     res.update("prover b", sizeof(b));


//     res.update("prover m_k", mk.size() * sizeof(mk[0]));
//     res.update("prover t_k", tk.size() * sizeof(tk[0]));
//     res.update("prover u_k", uk.size() * sizeof(uk[0]));
//     res.update("prover v_k", vk.size() * sizeof(vk[0]));
//     res.update("prover m_tilde_k", m_tilde_k.size() * sizeof(m_tilde_k[0]));
//     res.update("prover y_k", yk.size() * sizeof(yk[0]));

// }