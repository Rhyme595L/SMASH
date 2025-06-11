#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mp-circuit.hpp"
#include "emp-aby/simd_interface/arithmetic-circ.h"
#include "B2L.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <map>
#include <chrono>

namespace L2B {
using namespace emp;
using std::vector;

inline std::vector<TinyMAC<MultiIOBase>::LabeledShare> L2B(ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, TinyMAC<MultiIOBase>& tiny, int party, int num_party, MultiIO* io, ThreadPool* pool, const uint64_t& FIELD_SIZE, int l, Plaintext& x_arith, vector<Ciphertext>& x_cips) {

    Plaintext fd(FIELD_SIZE);
    mcl::Vint modulo(FIELD_SIZE);

    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bool(l);
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        r_bits[i] = tiny.distributed_share(bit_dis(gen));
    }
    auto [r_arith, r_cips] = B2L::B2L_for_L2B(elgl, lvt, tiny, party, num_party, io, pool, r_bits, FIELD_SIZE);
    Plaintext u, u_sum;
    vector<Ciphertext> u_cips(num_party);
    u = (x_arith - r_arith) % fd;
    u_cips[party - 1] = lvt->global_pk.encrypt(u);
    elgl->serialize_sendall(u);
    elgl->serialize_sendall(u_cips[party - 1]);

    u_sum = u;
    for (int i = 0; i < num_party; ++i) {
        if (i != party - 1) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i + 1);
            u_sum = (u_sum + tmp) % fd;
            elgl->deserialize_recv(u_cips[i], i + 1);
        }
    }
    vector<uint8_t> u_bits(l, 0);
    if (party == 1){
        uint64_t tmp = u_sum.get_message().getUint64();
        for (int i = l - 1; i >= 0; --i) {
            u_bits[i] = tmp & 1;
            tmp >>= 1;
        }
    }

    Plaintext sum = lvt->Reconstruct_easy(x_arith, elgl, io, pool, party, num_party, modulo);
    vector<uint8_t> bits(l, 0);
    if (party == 1){
        uint64_t tmp = sum.get_message().getUint64();
        for (int i = l - 1; i >= 0; --i) {
            bits[i] = tmp & 1;
            tmp >>= 1;
        }
    }

    for (int i = 0; i < l; ++i) {
        x_bool[i] = tiny.distributed_share(bits[i]);
    }

    if (tiny.bits_to_decimal(x_bool, FIELD_SIZE) != lvt->Reconstruct_easy(x_arith, elgl, io, pool, party, num_party, modulo).get_message().getUint64()) {
        cout << "Error in L2B" << endl;
        cout << "x_arith: " << lvt->Reconstruct_easy(x_arith, elgl, io, pool, party, num_party, modulo).get_message().getUint64() << endl;
        cout << "x_bool: " << tiny.bits_to_decimal(x_bool, FIELD_SIZE) << endl;
        exit(1);
    }
    return x_bool;
}
} // namespace L2B
