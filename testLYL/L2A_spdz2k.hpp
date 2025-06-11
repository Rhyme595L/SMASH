#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/spdz2k.hpp"
#include <vector>
#include <tuple>
#include <mcl/vint.hpp>
#include <map>
#include <iostream>
#include <iomanip>
#include <chrono>

namespace L2A_spdz2k {
using namespace emp;
using std::vector;
using std::tuple;
using std::map;

inline SPDZ2k<MultiIOBase>::LabeledShare L2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const Plaintext& x_plain,
    const vector<Ciphertext>& vec_cx,
    const uint64_t& fd,
    double& online_time,
    double& online_comm
) {
    SPDZ2k<MultiIOBase>::LabeledShare shared_x;
    Fr fd_fr; 
    fd_fr.setStr(std::to_string(fd));
    BLS12381Element G_fd(fd_fr);

    uint64_t r_spdz2k; r_spdz2k = spdz2k.rng() % fd; if(r_spdz2k < 0) r_spdz2k += fd;
    uint64_t r_spdz2k_mac = mulmod(r_spdz2k, spdz2k.mac_key, spdz2k_field_size);
    SPDZ2k<MultiIOBase>::LabeledShare shared_r;
    shared_r.value = r_spdz2k; shared_r.mac = r_spdz2k_mac; shared_r.owner = party; shared_r.field_size_ptr = &spdz2k_field_size;

    uint64_t x_spdz2k;
    Fr s = x_plain.get_message();
    x_spdz2k = s.getInt64();
    x_spdz2k %= fd; if (x_spdz2k < 0) x_spdz2k += fd;
    uint64_t x_spdz2k_mac = mulmod(x_spdz2k, spdz2k.mac_key, spdz2k_field_size);
    shared_x.value = x_spdz2k; shared_x.mac = x_spdz2k_mac; shared_x.owner = party; shared_x.field_size_ptr = &spdz2k_field_size;

    Plaintext r;
    r.assign(std::to_string(r_spdz2k));
    Ciphertext cr, count;
    cr = lvt->global_pk.encrypt(r);
    elgl->serialize_sendall(cr);

    vector<Ciphertext> vec_cr(num_party);
    vec_cr[party - 1] = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cr_i;
            elgl->deserialize_recv(cr_i, i);
            vec_cr[i - 1] = cr_i;
        }
    }

    count = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cr[i - 1];
        }
    }

    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    count += vec_cx[party - 1];
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cx[i - 1];
        }
    }
    
    BLS12381Element u = threshold_decrypt_<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);

    uint64_t u_int;
    SPDZ2k<MultiIOBase>::LabeledShare shared_u;
    shared_u = spdz2k.add(shared_x, shared_r);
    u_int = spdz2k.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    BLS12381Element uu(u_int);

    for (int i = 0; i <= num_party * 2; i++) {
        if (u == uu) {

            auto t2 = std::chrono::high_resolution_clock::now();
            int bytes_end = io->get_total_bytes_sent();
            double comm_kb = double(bytes_end - bytes_start) / 1024.0;
            double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
            // std::cout << std::fixed << std::setprecision(6)
            //           << "Communication: " << comm_kb << " KB, "
            //           << "Time: " << time_ms << " ms" << std::endl;

            online_time = time_ms;
            online_comm = comm_kb;
            return shared_x;
        }
        uu += G_fd;
    }
    throw std::runtime_error("L2A_spdz2k check failed: decrypted value != share sum");

}



inline SPDZ2k<MultiIOBase>::LabeledShare L2A_for_B2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const Plaintext& x_plain,
    vector<Ciphertext>& vec_cx,
    const uint64_t& fd
) {
    SPDZ2k<MultiIOBase>::LabeledShare shared_x;
    Fr fd_fr; 
    fd_fr.setStr(std::to_string(fd));
    BLS12381Element G_fd(fd_fr);

    uint64_t r_spdz2k; r_spdz2k = spdz2k.rng() % fd; if(r_spdz2k < 0) r_spdz2k += fd;
    SPDZ2k<MultiIOBase>::LabeledShare shared_r;
    shared_r = spdz2k.distributed_share(r_spdz2k);
    uint64_t x_spdz2k;
    Fr s = x_plain.get_message();
    x_spdz2k = s.getInt64();
    x_spdz2k %= fd; if (x_spdz2k < 0) x_spdz2k += fd;
    shared_x = spdz2k.distributed_share(x_spdz2k);

    Plaintext r;
    r.assign(std::to_string(r_spdz2k));
    Ciphertext cr, count;
    cr = lvt->global_pk.encrypt(r);
    elgl->serialize_sendall(cr);

    vector<Ciphertext> vec_cr(num_party);
    vec_cr[party - 1] = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cr_i;
            elgl->deserialize_recv(cr_i, i);
            vec_cr[i - 1] = cr_i;
        }
    }

    count = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cr[i - 1];
        }
    }

    vec_cx[party - 1] = lvt->global_pk.encrypt(x_plain);
    elgl->serialize_sendall(vec_cx[party - 1]);

    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cx_i;
            elgl->deserialize_recv(cx_i, i);
            vec_cx[i - 1] = cx_i;
        }
    }

    count += vec_cx[party - 1];
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cx[i - 1];
        }
    }
    BLS12381Element u = threshold_decrypt_<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    // BLS12381Element u = threshold_decrypt_<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    // Fr u = threshold_decrypt(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    uint64_t u_int;
    // u_int.setStr(u.getStr());
    SPDZ2k<MultiIOBase>::LabeledShare shared_u;
    shared_u = spdz2k.add(shared_x, shared_r);
    u_int = spdz2k.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    Fr u_int_fr; 
    u_int_fr.setStr(std::to_string(u_int));
    BLS12381Element uu(u_int_fr);
    
    for (int i = 0; i <= num_party * 2; i++) {
        if (u == uu) {
            return shared_x;
        }
        uu += G_fd;
    }
    throw std::runtime_error("L2A_for_B2A_spdz2k check failed: decrypted value != share sum");
}

} // namespace L2A_spdz2k