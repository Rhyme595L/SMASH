#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mascot.hpp"
#include "B2A_mascot.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <map>
#include <chrono>

namespace A2B_mascot {
using namespace emp;
using std::vector;

inline vector<TinyMAC<MultiIOBase>::LabeledShare> A2B(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    MASCOT<MultiIOBase>& mascot,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const mcl::Vint& FIELD_SIZE,
    int l,
    const MASCOT<MultiIOBase>::LabeledShare& x_arith,
    double& online_time,
    double& online_comm
) {
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bool(l);
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) r_bits[i] = tiny.distributed_share(bit_dis(gen));
    MASCOT<MultiIOBase>::LabeledShare r_arith;
    r_arith = B2A_mascot::B2A_for_A2B(elgl, lvt, tiny, mascot, party, num_party, io, pool, FIELD_SIZE, r_bits);
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();
    MASCOT<MultiIOBase>::LabeledShare x_plus_r;
    x_plus_r = mascot.add(x_arith, r_arith);
    mcl::Vint u;
    u = mascot.reconstruct(x_plus_r);
    u = (u + FIELD_SIZE) % FIELD_SIZE;
    vector<uint8_t> u_bits(l, 0);
    mcl::Vint tmp = u;
    for (int i = 0; i < l; ++i) {
        u_bits[i] = (tmp & 1).getLow32bit();
        tmp >>= 1;
    }
    vector<TinyMAC<MultiIOBase>::LabeledShare> u_bool(l);
    for (int i = 0; i < l; ++i) u_bool[i] = tiny.distributed_share(u_bits[i]);
    for (int i = 0; i < l; ++i) x_bool[i] = tiny.add(u_bool[i], r_bits[i]);
    auto t2 = std::chrono::high_resolution_clock::now();
    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb << " KB, "
              << "Time: " << time_ms << " ms" << std::endl;
    online_time = time_ms;
    online_comm = comm_kb;
    return x_bool;
}
} // namespace A2B_mascot 