#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mascot.hpp"
#include "L2A_mascot.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <random>
#include <map>
#include <stdexcept>
#include <chrono>

namespace B2A_mascot {
using namespace emp;
using std::vector;

inline MASCOT<MultiIOBase>::LabeledShare B2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    MASCOT<MultiIOBase>& mascot,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const mcl::Vint& FIELD_SIZE,
    const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits,
    double& online_time,
    double& online_comm
) {
    int l = x_bits.size();
    vector<MASCOT<MultiIOBase>::LabeledShare> shared_x(l); 
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l), u_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) r_bits[i] = tiny.distributed_share(bit_dis(gen));
    vector<MASCOT<MultiIOBase>::LabeledShare> shared_r(l);
    shared_x.resize(l);

    vector<Ciphertext> x_cipher(l), r_cipher(l), x_lut_ciphers(num_party);
    vector<Plaintext> x_plain(l), r_plain(l); 
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(r_bits[i].value)); 
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);

        vector<Ciphertext> r_ciphers;
        r_ciphers.resize(num_party); 
        auto result = lvt->lookup_online(plain_i, r_cipher[i], r_ciphers);
        r_plain[i] = std::get<0>(result);
        r_ciphers = std::get<1>(result);  
        
        shared_r[i] = L2A_mascot::L2A_for_B2A(elgl, lvt, mascot, party, num_party, io, pool, r_plain[i], r_ciphers, FIELD_SIZE);
        if (shared_r[i].value == 0) shared_r[i].value = 0;
    }

    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        vector<Ciphertext> x_ciphers;
        x_ciphers.resize(num_party);  
        auto result = lvt->lookup_online(plain_i, x_cipher[i], x_ciphers);
        x_plain[i] = std::get<0>(result);  
        auto lut_ciphers = std::get<1>(result);  
    }

    int skip_bytes_start = io->get_total_bytes_sent();
    auto skip_t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < l; i++) {
        shared_x[i] = L2A_mascot::L2A_for_B2A(elgl, lvt, mascot, party, num_party, io, pool, x_plain[i], x_lut_ciphers, FIELD_SIZE);
        if (shared_x[i].value == 0) shared_x[i].value = 0;
    }
    int skip_bytes_end = io->get_total_bytes_sent();
    auto skip_t2 = std::chrono::high_resolution_clock::now();
    double skip_comm_kb = double(skip_bytes_end - skip_bytes_start) / 1024.0;
    double skip_time_ms = std::chrono::duration<double, std::milli>(skip_t2 - skip_t1).count();

    for (int i = 0; i < l; ++i) u_bits[i] = tiny.add(x_bits[i], r_bits[i]);

    for (int i = 0; i < l; ++i) {
        auto mascot_u = mascot.add(shared_x[i], shared_r[i]);
        auto m = mascot.multiply(shared_x[i], shared_r[i]);
        auto mascot_open = mascot.reconstruct(m);
        mascot_open = (mascot_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        m = m * 2;
        m.value = (FIELD_SIZE - m.value) % FIELD_SIZE;
        if (m.value < 0) m.value += FIELD_SIZE;
        m.mac = (FIELD_SIZE - m.mac) % FIELD_SIZE;
        if (m.mac < 0) m.mac += FIELD_SIZE;

        mascot_u = mascot.add(mascot_u, m);
        mascot_open = mascot.reconstruct(mascot_u);
        mascot_open = (mascot_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        uint8_t tiny_u = tiny.reconstruct(tiny.add(x_bits[i], r_bits[i]));
        if (((2 + tiny_u % 2)+2)%2 != ((2 + mascot_open % 2)+2)%2) {
            throw std::runtime_error("B2A_mascot check failed: decrypted value != share sum");
        }
    }
    MASCOT<MultiIOBase>::LabeledShare share_x_decimal;
    share_x_decimal.value = 0;
    share_x_decimal.mac = 0;
    share_x_decimal.owner = party;
    share_x_decimal.field_size_ptr = &FIELD_SIZE;
    for (int i = 0; i < l; ++i) {
        share_x_decimal = share_x_decimal * 2 + shared_x[i];
    }

    int bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0 - skip_comm_kb;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count() - skip_time_ms;
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb << " KB, "
              << "Time: " << time_ms << " ms" << std::endl;

    online_time = time_ms;
    online_comm = comm_kb;

    return share_x_decimal; 
}

inline MASCOT<MultiIOBase>::LabeledShare B2A_for_A2B(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    MASCOT<MultiIOBase>& mascot,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const mcl::Vint& FIELD_SIZE,
    const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits
) {
    int l = x_bits.size();
    vector<MASCOT<MultiIOBase>::LabeledShare> shared_x(l); 
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l), u_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) r_bits[i] = tiny.distributed_share(bit_dis(gen));
    vector<MASCOT<MultiIOBase>::LabeledShare> shared_r(l);
    shared_x.resize(l);

    vector<Ciphertext> x_cipher(l), r_cipher(l), x_lut_ciphers(num_party);
    vector<Plaintext> x_plain(l), r_plain(l); 
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(r_bits[i].value)); 
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);

        vector<Ciphertext> r_ciphers;
        r_ciphers.resize(num_party); 
        auto result = lvt->lookup_online(plain_i, r_cipher[i], r_ciphers);
        r_plain[i] = std::get<0>(result);
        r_ciphers = std::get<1>(result);  
        
        shared_r[i] = L2A_mascot::L2A_for_B2A(elgl, lvt, mascot, party, num_party, io, pool, r_plain[i], r_ciphers, FIELD_SIZE);
        if (shared_r[i].value == 0) shared_r[i].value = 0;
    }

    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        vector<Ciphertext> x_ciphers;
        x_ciphers.resize(num_party);  
        auto result = lvt->lookup_online(plain_i, x_cipher[i], x_ciphers);
        x_plain[i] = std::get<0>(result);  
        auto lut_ciphers = std::get<1>(result);  
    }

    int skip_bytes_start = io->get_total_bytes_sent();
    auto skip_t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < l; i++) {
        shared_x[i] = L2A_mascot::L2A_for_B2A(elgl, lvt, mascot, party, num_party, io, pool, x_plain[i], x_lut_ciphers, FIELD_SIZE);
        if (shared_x[i].value == 0) shared_x[i].value = 0;
    }
    int skip_bytes_end = io->get_total_bytes_sent();
    auto skip_t2 = std::chrono::high_resolution_clock::now();
    double skip_comm_kb = double(skip_bytes_end - skip_bytes_start) / 1024.0;
    double skip_time_ms = std::chrono::duration<double, std::milli>(skip_t2 - skip_t1).count();

    for (int i = 0; i < l; ++i) u_bits[i] = tiny.add(x_bits[i], r_bits[i]);

    for (int i = 0; i < l; ++i) {
        auto mascot_u = mascot.add(shared_x[i], shared_r[i]);
        auto m = mascot.multiply(shared_x[i], shared_r[i]);
        auto mascot_open = mascot.reconstruct(m);
        mascot_open = (mascot_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        m = m * 2;
        m.value = (FIELD_SIZE - m.value) % FIELD_SIZE;
        if (m.value < 0) m.value += FIELD_SIZE;
        m.mac = (FIELD_SIZE - m.mac) % FIELD_SIZE;
        if (m.mac < 0) m.mac += FIELD_SIZE;

        mascot_u = mascot.add(mascot_u, m);
        mascot_open = mascot.reconstruct(mascot_u);
        mascot_open = (mascot_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        uint8_t tiny_u = tiny.reconstruct(tiny.add(x_bits[i], r_bits[i]));
        if (((2 + tiny_u % 2)+2)%2 != ((2 + mascot_open % 2)+2)%2) {
            throw std::runtime_error("B2A_for_A2B_mascot check failed: decrypted value != share sum");
        }
    }
    MASCOT<MultiIOBase>::LabeledShare share_x_decimal;
    share_x_decimal.value = 0;
    share_x_decimal.mac = 0;
    share_x_decimal.owner = party;
    share_x_decimal.field_size_ptr = &FIELD_SIZE;
    for (int i = 0; i < l; ++i) {
        share_x_decimal = share_x_decimal * 2 + shared_x[i];
    }

    return share_x_decimal; 
}
} // namespace B2A_mascot