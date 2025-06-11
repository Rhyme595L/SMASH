#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/mascot.hpp"
#include <vector>
#include <tuple>
#include <mcl/vint.hpp>
#include <map>
#include <iostream>
#include <iomanip>
#include <chrono>

namespace A2L_mascot {
using namespace emp;
using std::vector;
using std::tuple;
using std::map;

inline tuple<Plaintext, vector<Ciphertext>> A2L(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    MASCOT<MultiIOBase>& mascot,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const MASCOT<MultiIOBase>::LabeledShare& shared_x,
    const mcl::Vint& fd,
    double& online_time,
    double& online_comm
) {
    Plaintext x;
    vector<Ciphertext> vec_cx(num_party);
    Fr fd_fr; 
    fd_fr.setStr(fd.getStr());
    BLS12381Element G_fd(fd_fr);

    mcl::Vint r_mascot; r_mascot.setRand(fd);
    MASCOT<MultiIOBase>::LabeledShare shared_r = mascot.distributed_share(r_mascot);
    mcl::Vint rval = shared_r.value; rval %= fd; if (rval < 0) rval += fd;
    Plaintext r;
    r.assign(rval.getStr());

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

    mcl::Vint xval = shared_x.value; xval %= fd; if (xval < 0) xval += fd;
    x.assign(xval.getStr());
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
    
    MASCOT<MultiIOBase>::LabeledShare shared_u = mascot.add(shared_x, shared_r);
    mcl::Vint u_int = mascot.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    Fr u_int_fr; 
    u_int_fr.setStr(u_int.getStr());
    BLS12381Element uu(u_int_fr);

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
    throw std::runtime_error("A2L_mascot check failed: decrypted value != share sum");
}

} // namespace A2L_mascot