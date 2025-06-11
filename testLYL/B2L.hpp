#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <random>
#include <map>
#include <stdexcept>
#include <chrono>
#include <tuple>

namespace B2L {
using namespace emp;
using std::vector;

inline tuple<Plaintext, vector<Ciphertext>> B2L(ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, TinyMAC<MultiIOBase>& tiny, int party, int num_party, MultiIO* io, ThreadPool* pool, const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits, const uint64_t& modulus) {

    int l = x_bits.size();
    vector<Plaintext> shared_x(l); 
    Plaintext fd(modulus);
    
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        r_bits[i] = tiny.distributed_share(bit_dis(gen));
    }

    vector<Ciphertext> x_cipher(l), r_cipher(l);
    vector<Plaintext> x_plain(l), r_plain(l);
    vector<uint8_t> rr(l);
    
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        vector<Ciphertext> r_lut_ciphers(num_party);
        plain_i.assign(std::to_string(r_bits[i].value));
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto out1 = lvt->lookup_online_easy(plain_i);
        r_plain[i] = out1;
        rr[i] = r_plain[i].get_message().getUint64() % 2;
    }

    vector<uint8_t> xx(l);
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        vector<Ciphertext> x_lut_ciphers(num_party);
        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto out1 = lvt->lookup_online_easy(plain_i);
        x_plain[i] = out1;
        xx[i] = x_plain[i].get_message().getUint64() % 2;
    }

    Plaintext x, r; x.assign("0"); r.assign("0");
    for (int i = 0; i < l; ++i) {
        x = (x + x + x_plain[i]) % fd;
    }

    for (int i = 0; i < l; ++i) {
        uint8_t h = xx[i] ^ rr[i];
        Plaintext hh; hh.assign(std::to_string(h));
        uint64_t outt = lvt->Reconstruct_easy(hh, elgl, io, pool, party, num_party, 2).get_message().getUint64();
        uint8_t out_ = tiny.reconstruct(tiny.add(x_bits[i],r_bits[i]));
        if (outt != out_) {
            std::cerr << "Error: B2L output does not match expected value." << std::endl;
            cout << " Expected: " << outt << ", Got: " << to_string(out_) << std::endl;
            cout << "x: " << tiny.bits_to_decimal(x_bits, modulus) << endl;
            cout << "x: " << lvt->Reconstruct_easy(x, elgl, io, pool, party, num_party, modulus).get_message().getUint64() << endl;
            throw std::runtime_error("B2L output mismatch");
        }
    }    

    vector<Ciphertext> x_cip(num_party);
    x_cip[party - 1] = lvt->global_pk.encrypt(x);
    elgl->serialize_sendall(x_cip[party - 1]);

    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            elgl->deserialize_recv(x_cip[i - 1], i);
        }
    }

    return std::make_tuple(x, x_cip);
}


inline tuple<Plaintext, vector<Ciphertext>> B2L_for_L2B(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits,
    const uint64_t& modulus
) {
    int l = x_bits.size();
    vector<Plaintext> shared_x(l); 
    Plaintext fd(modulus);
    
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        r_bits[i] = tiny.distributed_share(bit_dis(gen));
    }

    vector<Ciphertext> x_cipher(l), r_cipher(l);
    vector<Plaintext> x_plain(l), r_plain(l);
    vector<uint8_t> rr(l);
    
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        vector<Ciphertext> r_lut_ciphers(num_party);
        plain_i.assign(std::to_string(r_bits[i].value));
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto out1 = lvt->lookup_online_easy(plain_i);
        r_plain[i] = out1;
        rr[i] = r_plain[i].get_message().getUint64() % 2;
    }
    
    vector<uint8_t> xx(l);
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        vector<Ciphertext> x_lut_ciphers(num_party);
        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto out1 = lvt->lookup_online_easy(plain_i);
        x_plain[i] = out1;
        xx[i] = x_plain[i].get_message().getUint64() % 2;
    }

    Plaintext x, r; x.assign("0"); r.assign("0");
    for (int i = 0; i < l; ++i) {
        x = (x + x + x_plain[i]) % fd;
    }

    for (int i = 0; i < l; ++i) {
        uint8_t h = xx[i] ^ rr[i];
        Plaintext hh; hh.assign(std::to_string(h));
        uint64_t outt = lvt->Reconstruct_easy(hh, elgl, io, pool, party, num_party, 2).get_message().getUint64();
        uint8_t out_ = tiny.reconstruct(tiny.add(x_bits[i],r_bits[i]));
        if (outt != out_) {
            std::cerr << "Error in L2B: B2L output does not match expected value." << std::endl;
            cout << " Expected: " << outt << ", Got: " << to_string(out_) << std::endl;
            cout << "x: " << tiny.bits_to_decimal(x_bits, modulus) << endl;
            cout << "x: " << lvt->Reconstruct_easy(x, elgl, io, pool, party, num_party, modulus).get_message().getUint64() << endl;
            throw std::runtime_error("B2L output mismatch in L2B");
        }
    }    

    vector<Ciphertext> x_cip(num_party);
    x_cip[party - 1] = lvt->global_pk.encrypt(x);
    elgl->serialize_sendall(x_cip[party - 1]);

    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            elgl->deserialize_recv(x_cip[i - 1], i);
        }
    }
    return std::make_tuple(x, x_cip);
}

}

inline std::vector<uint8_t> get_first_12_bits(const std::vector<uint8_t>& input) {
    if (input.size() != 24) {
        throw std::invalid_argument("Input vector must have exactly 24 bits.");
    }
    return std::vector<uint8_t>(input.begin(), input.begin() + 12);
}

inline std::vector<uint8_t> get_last_12_bits(const std::vector<uint8_t>& input) {
    if (input.size() != 24) {
        throw std::invalid_argument("Input vector must have exactly 24 bits.");
    }
    return std::vector<uint8_t>(input.begin() + 12, input.end());
}