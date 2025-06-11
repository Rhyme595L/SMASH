#pragma once
#include "testLLM/FixedPointConverter.h"
#include "elgl_interface.hpp"
#include <vector>
#include <random>
#include <chrono>
#include <cassert>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <map>

namespace emp {

inline uint8_t xor_mac(uint8_t a, uint8_t b) { return a ^ b; }

// TinyMAC: 恶意安全布尔MPC（不诚实多数）
template <typename IO>
class TinyMAC {
public:
    ELGL<IO>* elgl;
    int party;
    int num_parties;
    std::mt19937_64 rng;
    uint8_t mac_key; // 单比特MAC密钥

    struct LabeledShare {
        uint8_t value; // 比特份额
        uint8_t mac;   // MAC
        int owner;
        const uint8_t* field_size_ptr;
        LabeledShare() : value(0), mac(0), owner(0), field_size_ptr(nullptr) {}
        LabeledShare(uint8_t v, uint8_t m, int o, const uint8_t* fs) : value(v), mac(m), owner(o), field_size_ptr(fs) {}
        void pack(std::stringstream& ss) const {
            ss << int(value) << " " << int(mac) << " " << owner << " ";
        }
        void unpack(std::stringstream& ss) {
            int v, m;
            ss >> v >> m >> owner;
            value = v & 1;
            mac = m & 1;
        }
        LabeledShare operator^(const LabeledShare& rhs) const {
            return LabeledShare(value ^ rhs.value, mac ^ rhs.mac, owner, field_size_ptr);
        }
    };

    struct Triple {
        uint8_t a, b, c, mac_a, mac_b, mac_c;
        Triple() : a(0), b(0), c(0), mac_a(0), mac_b(0), mac_c(0) {}
        Triple(uint8_t a, uint8_t b, uint8_t c, uint8_t ma, uint8_t mb, uint8_t mc)
            : a(a), b(b), c(c), mac_a(ma), mac_b(mb), mac_c(mc) {}
        void pack(std::stringstream& ss) const {
            ss << int(a) << " " << int(b) << " " << int(c) << " "
               << int(mac_a) << " " << int(mac_b) << " " << int(mac_c) << " ";
        }
        void unpack(std::stringstream& ss) {
            int va, vb, vc, ma, mb, mc;
            ss >> va >> vb >> vc >> ma >> mb >> mc;
            a = va & 1; b = vb & 1; c = vc & 1;
            mac_a = ma & 1; mac_b = mb & 1; mac_c = mc & 1;
        }
    };

    std::vector<Triple> triples_pool;

    void precompute_triples(size_t num_triples) {
        for (size_t i = 0; i < num_triples; i++) {
            generate_triple();
        }
    }
    void generate_triple() {
        uint8_t a_local = rng() & 1;
        uint8_t b_local = rng() & 1;
        std::stringstream ss;
        ss << int(a_local) << " " << int(b_local) << " ";
        elgl->serialize_sendall_with_tag(ss, 2000 * party + party);
        uint8_t a_full = a_local, b_full = b_local;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 2000 * i + i);
                int other_a, other_b;
                ss_recv >> other_a >> other_b;
                a_full ^= (other_a & 1);
                b_full ^= (other_b & 1);
            }
        }
        uint8_t c_full = a_full & b_full;
        uint8_t c_local = (party == 1) ? c_full : 0;
        uint8_t mac_a = a_local & mac_key;
        uint8_t mac_b = b_local & mac_key;
        uint8_t mac_c = c_local & mac_key;
        triples_pool.emplace_back(a_local, b_local, c_local, mac_a, mac_b, mac_c);
    }
    Triple get_triple() {
        if (triples_pool.empty()) {
            precompute_triples(10);
        }
        Triple t = triples_pool.back();
        triples_pool.pop_back();
        return t;
    }
    bool check_mac(uint8_t value, uint8_t mac) const {
        return mac == (value & mac_key);
    }
    TinyMAC(ELGL<IO>* elgl_instance) : elgl(elgl_instance) {
        party = elgl->party;
        num_parties = elgl->num_party;
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count() + party;
        rng.seed(seed);
        uint8_t local_mac_key = rng() & 1;
        {
            std::stringstream ss;
            ss << int(local_mac_key) << " ";
            elgl->serialize_sendall_with_tag(ss, 3000 * party + party);
        }
        uint8_t global_mac_key = local_mac_key;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 3000 * i + i);
                int other_key; ss_recv >> other_key;
                global_mac_key ^= (other_key & 1);
            }
        }
        mac_key = global_mac_key & 1;
        precompute_triples(20);
    }
    ~TinyMAC() {}
    // 分发布尔份额
    LabeledShare distributed_share(uint8_t xi) {
        std::vector<uint8_t> shares(num_parties, 0);
        uint8_t remain = xi & 1;
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            uint8_t tmp = rng() & 1;
            shares[i-1] = tmp;
            remain ^= tmp;
        }
        shares[party-1] = remain;
        std::vector<uint8_t> received(num_parties, 0);
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            if (party < i) {
                std::stringstream ss;
                uint8_t mac = shares[i-1] & mac_key;
                ss << int(shares[i-1]) << " " << int(mac) << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                int share, mac2; ss_recv >> share >> mac2;
                assert(check_mac(share & 1, mac2 & 1));
                received[i-1] = share & 1;
            } else {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                int share, mac2; ss_recv >> share >> mac2;
                assert(check_mac(share & 1, mac2 & 1));
                received[i-1] = share & 1;
                std::stringstream ss;
                uint8_t mac = shares[i-1] & mac_key;
                ss << int(shares[i-1]) << " " << int(mac) << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
            }
        }
        received[party-1] = remain;
        uint8_t local_share = 0;
        for (int i = 0; i < num_parties; ++i) {
            local_share ^= received[i];
        }
        uint8_t mac = local_share & mac_key;
        return LabeledShare(local_share, mac, party, nullptr);
    }
    // 重构布尔秘密
    uint8_t reconstruct(const LabeledShare& share) {
        std::stringstream ss;
        share.pack(ss);
        elgl->serialize_sendall_with_tag(ss, 1000 * party + party);
        uint8_t result = share.value & 1;
        for (int i = 1; i <= num_parties; i++) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 1000 * i + i);
                LabeledShare other_share;
                other_share.unpack(ss_recv);
                assert(check_mac(other_share.value, other_share.mac));
                result ^= (other_share.value & 1);
            }
        }
        return result & 1;
    }
    // 按位异或
    LabeledShare add(const LabeledShare& x, const LabeledShare& y) {
        return x ^ y;
    }
    // 按位与（带MAC）
    LabeledShare multiply(const LabeledShare& x, const LabeledShare& y) {
        Triple t = get_triple();
        uint8_t epsilon = (x.value ^ t.a) & 1;
        uint8_t delta = (y.value ^ t.b) & 1;
        LabeledShare eps_share(
            epsilon,
            (x.mac ^ t.mac_a) & 1,
            party,
            nullptr
        );
        LabeledShare del_share(
            delta,
            (y.mac ^ t.mac_b) & 1,
            party,
            nullptr
        );
        uint8_t epsilon_open = reconstruct(eps_share) & 1;
        uint8_t delta_open = reconstruct(del_share) & 1;
        uint8_t z_value = (t.c ^ (epsilon_open & t.b) ^ (delta_open & t.a)) & 1;
        if (party == 1) {
            z_value ^= (epsilon_open & delta_open) & 1;
        }
        uint8_t z_mac = (t.mac_c ^ (epsilon_open & t.mac_b) ^ (delta_open & t.mac_a)) & 1;
        if (party == 1) {
            z_mac ^= ((epsilon_open & delta_open) & mac_key) & 1;
        }
        assert(check_mac(z_value, z_mac));
        return LabeledShare(z_value, z_mac, party, nullptr);
    }

    void extract_first_12_shares(std::vector<LabeledShare>& out, std::vector<LabeledShare>& input) {
        if (input.size() != 24) {
            throw std::invalid_argument("Input vector must have exactly 24 shares.");
        }
        out = std::vector<LabeledShare>(input.begin(), input.begin() + 12);
        return;
    }

    void extract_last_12_shares(std::vector<LabeledShare>& out, std::vector<LabeledShare>& input) {
        if (input.size() != 24) {
            throw std::invalid_argument("Input vector must have exactly 24 shares.");
        }
        out = std::vector<LabeledShare>(input.begin() + 12, input.end());
        return;
    }
    // 将二进制比特拼接成十进制数的函数
    uint64_t bits_to_decimal(const std::vector<LabeledShare>& shares, uint64_t field) {
        std::string binary_str;
        for (const auto& share : shares) {
            // 使用 reconstruct 恢复出每个比特
            int bit = this->reconstruct(share);
            binary_str += std::to_string(bit);
        }
        return std::bitset<64>(binary_str).to_ullong() % field; // 假设总比特数不超过 64 位
    }
};

} // namespace emp

