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

namespace A2L_spdz2k {
using namespace emp;
using std::vector;
using std::tuple;
using std::map;

inline tuple<Plaintext, vector<Ciphertext>> A2L(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const SPDZ2k<MultiIOBase>::LabeledShare& shared_x,
    const uint64_t& fd,
    double& online_time,
    double& online_comm
) {
    Plaintext x;
    vector<Ciphertext> vec_cx(num_party);
    Fr fd_fr; 
    fd_fr.setStr(std::to_string(fd));
    BLS12381Element G_fd(fd_fr);

    uint64_t r_spdz2k; r_spdz2k = spdz2k.rng() % fd; if(r_spdz2k < 0) r_spdz2k += fd;
    uint64_t r_spdz2k_mac = mulmod(r_spdz2k, spdz2k.mac_key, spdz2k_field_size);
    SPDZ2k<MultiIOBase>::LabeledShare shared_r;
    shared_r.value = r_spdz2k; shared_r.mac = r_spdz2k_mac; shared_r.owner = party; shared_r.field_size_ptr = &spdz2k_field_size;
    Plaintext r;
    r.assign(std::to_string(r_spdz2k));

    Ciphertext cx, cr, count;
    cr = lvt->global_pk.encrypt(r);
    elgl->serialize_sendall(cr);
    count = cr;

    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cr_i;
            elgl->deserialize_recv(cr_i, i);
            count += cr_i;
        }
    }

    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    uint64_t xval = shared_x.value; xval %= fd; if (xval < 0) xval += fd;
    x.assign(std::to_string(xval));
    cx = lvt->global_pk.encrypt(x);
    count = count + cx;
    vec_cx[party - 1] = cx;

    elgl->serialize_sendall(cx);
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cx_i;
            elgl->deserialize_recv(cx_i, i);
            count += cx_i;
            vec_cx[i - 1] = cx_i;
        }
    }

    
    BLS12381Element u = threshold_decrypt_<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    
    SPDZ2k<MultiIOBase>::LabeledShare shared_u = spdz2k.add(shared_x, shared_r);
    uint64_t u_int = spdz2k.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    BLS12381Element uu(u_int);

    for (int i = 0; i <= num_party * 2; i++) {
        if (u == uu) {

            auto t2 = std::chrono::high_resolution_clock::now();
            int bytes_end = io->get_total_bytes_sent();
            double comm_kb = double(bytes_end - bytes_start) / 1024.0;
            double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
            online_time = time_ms;
            online_comm = comm_kb;
            return std::make_tuple(x, vec_cx);
        }
        uu += G_fd;
    }
    throw std::runtime_error("A2L_spdz2k check failed: decrypted value != share sum");
}

} // namespace A2L_spdz2k