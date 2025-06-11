#pragma once

#include "elgl_interface.hpp"
#include "testLLM/FixedPointConverter.h"
#include <vector>
#include <random>
#include <chrono>
#include <cassert>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <map>

// SPDZ2k整数域，k=64
const uint64_t spdz2k_field_size = (1ULL << 63); // 2^63-1，示例用素数

namespace emp {

inline uint64_t mulmod(uint64_t a, uint64_t b, uint64_t mod) {
    return static_cast<uint64_t>((__uint128_t)a * b % mod);
}

template <typename IO>
class SPDZ2k {
public:
    ELGL<IO>* elgl;
    int party;
    int num_parties;
    std::mutex mtx;
    std::condition_variable cv;
    std::mt19937_64 rng;
    uint64_t mac_key;

    struct LabeledShare {
        uint64_t value;
        uint64_t mac;
        int owner;
        const uint64_t* field_size_ptr;
        LabeledShare() : value(0), mac(0), owner(0), field_size_ptr(nullptr) {}
        LabeledShare(uint64_t v, uint64_t m, int o, const uint64_t* fs) : value(v), mac(m), owner(o), field_size_ptr(fs) {}
        void pack(std::stringstream& ss) const {
            ss << value << " " << mac << " " << owner << " ";
        }
        void unpack(std::stringstream& ss) {
            ss >> value >> mac >> owner;
        }
        LabeledShare operator+(const LabeledShare& rhs) const {
            uint64_t fs = spdz2k_field_size;
            uint64_t v = (value + rhs.value) % fs;
            uint64_t m = (mac + rhs.mac) % fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
        LabeledShare operator*(uint64_t scalar) const {
            uint64_t fs = spdz2k_field_size;
            uint64_t s = scalar % fs;
            uint64_t v = (value * s) % fs;
            uint64_t m = (mac * s) % fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
    };

    struct Triple {
        uint64_t a, b, c, mac_a, mac_b, mac_c;
        Triple() : a(0), b(0), c(0), mac_a(0), mac_b(0), mac_c(0) {}
        Triple(uint64_t a, uint64_t b, uint64_t c, uint64_t ma, uint64_t mb, uint64_t mc)
            : a(a), b(b), c(c), mac_a(ma), mac_b(mb), mac_c(mc) {}
        void pack(std::stringstream& ss) const {
            ss << a << " " << b << " " << c << " " << mac_a << " " << mac_b << " " << mac_c << " ";
        }
        void unpack(std::stringstream& ss) {
            ss >> a >> b >> c >> mac_a >> mac_b >> mac_c;
        }
    };

    std::vector<Triple> triples_pool;

    void precompute_triples(size_t num_triples) {
        for (size_t i = 0; i < num_triples; i++) {
            generate_triple();
        }
    }
    void generate_triple() {
        uint64_t fs = spdz2k_field_size;
        uint64_t a_local = rng() % fs;
        uint64_t b_local = rng() % fs;
        std::stringstream ss;
        ss << a_local << " " << b_local << " ";
        elgl->serialize_sendall_with_tag(ss, 2000 * party + party);
        uint64_t a_full = a_local, b_full = b_local;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 2000 * i + i);
                uint64_t other_a, other_b;
                ss_recv >> other_a >> other_b;
                a_full = (a_full + other_a) % fs;
                b_full = (b_full + other_b) % fs;
            }
        }
        uint64_t c_full = mulmod(a_full, b_full, fs);
        uint64_t c_local = (party == 1) ? c_full : 0;
        uint64_t mac_a = mulmod(a_local, mac_key, fs);
        uint64_t mac_b = mulmod(b_local, mac_key, fs);
        uint64_t mac_c = mulmod(c_local, mac_key, fs);
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
    bool check_mac(uint64_t value, uint64_t mac) const {
        return mac == mulmod(value, mac_key, spdz2k_field_size);
    }
    void send_value_and_mac(uint64_t value, uint64_t mac, int dst) {
        std::stringstream ss;
        ss << value << " " << mac << " ";
        elgl->serialize_send_with_tag(ss, dst, 5000 * dst + party);
    }
    std::pair<uint64_t, uint64_t> recv_value_and_mac(int src) {
        std::stringstream ss;
        elgl->deserialize_recv_with_tag(ss, src, 5000 * party + src);
        uint64_t value, mac;
        ss >> value >> mac;
        return {value, mac};
    }
    SPDZ2k(ELGL<IO>* elgl_instance) : elgl(elgl_instance) {
        party = elgl->party;
        num_parties = elgl->num_party;
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count() + party;
        rng.seed(seed);
        uint64_t local_mac_key = rng() % spdz2k_field_size;
        {
            std::stringstream ss;
            ss << local_mac_key << " ";
            elgl->serialize_sendall_with_tag(ss, 3000 * party + party);
        }
        uint64_t global_mac_key = local_mac_key;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 3000 * i + i);
                uint64_t other_key;
                ss_recv >> other_key;
                global_mac_key = (global_mac_key + other_key) % spdz2k_field_size;
            }
        }
        mac_key = global_mac_key;
        precompute_triples(20);
    }
    ~SPDZ2k() {}

    LabeledShare distributed_share_(uint64_t xi) {
        uint64_t fs = spdz2k_field_size;
        uint64_t local_share = xi % fs;
        uint64_t mac = mulmod(local_share, mac_key, fs);
        return LabeledShare(local_share, mac, party, &spdz2k_field_size);
    }

    LabeledShare distributed_share(uint64_t xi) {
        uint64_t fs = spdz2k_field_size;
        std::vector<uint64_t> shares(num_parties, 0);
        uint64_t remain = xi % fs;
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            uint64_t tmp = rng() % fs;
            shares[i-1] = tmp;
            remain = (remain + fs - tmp) % fs;
        }
        shares[party-1] = remain;
        std::vector<uint64_t> received(num_parties, 0);
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            if (party < i) {
                std::stringstream ss;
                uint64_t mac = mulmod(shares[i-1], mac_key, fs);
                ss << shares[i-1] << " " << mac << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                uint64_t share, mac2;
                ss_recv >> share >> mac2;
                assert(check_mac(share, mac2));
                received[i-1] = share % fs;
            } else {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                uint64_t share, mac2;
                ss_recv >> share >> mac2;
                assert(check_mac(share, mac2));
                received[i-1] = share % fs;
                std::stringstream ss;
                uint64_t mac = mulmod(shares[i-1], mac_key, fs);
                ss << shares[i-1] << " " << mac << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
            }
        }
        received[party-1] = remain;
        uint64_t local_share = 0;
        for (int i = 0; i < num_parties; ++i) {
            local_share = (local_share + received[i]) % fs;
        }
        uint64_t mac = mulmod(local_share, mac_key, fs);
        return LabeledShare(local_share, mac, party, &spdz2k_field_size);
    }
    uint64_t reconstruct(const LabeledShare& share) {
        uint64_t fs = spdz2k_field_size;
        std::stringstream ss;
        share.pack(ss);
        elgl->serialize_sendall_with_tag(ss, 1000 * party + party);
        uint64_t result = share.value % fs;
        for (int i = 1; i <= num_parties; i++) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 1000 * i + i);
                LabeledShare other_share;
                other_share.unpack(ss_recv);
                other_share.field_size_ptr = &spdz2k_field_size;
                assert(check_mac(other_share.value, other_share.mac));
                uint64_t v = other_share.value % fs;
                result = (result + v) % fs;
            }
        }
        return result % fs;
    }
    LabeledShare add(const LabeledShare& x, const LabeledShare& y) {
        return x + y;
    }
    LabeledShare mul_const(const LabeledShare& x, uint64_t scalar) {
        return x * scalar;
    }
    LabeledShare multiply(const LabeledShare& x, const LabeledShare& y) {
        Triple t = get_triple();
        uint64_t fs = spdz2k_field_size;
        uint64_t epsilon = (x.value + fs - t.a) % fs;
        uint64_t delta = (y.value + fs - t.b) % fs;
        LabeledShare eps_share(
            epsilon,
            (x.mac + fs - t.mac_a) % fs,
            party,
            &spdz2k_field_size
        );
        LabeledShare del_share(
            delta,
            (y.mac + fs - t.mac_b) % fs,
            party,
            &spdz2k_field_size
        );
        uint64_t epsilon_open = reconstruct(eps_share);
        uint64_t delta_open = reconstruct(del_share);
        uint64_t z_value = (t.c + mulmod(epsilon_open, t.b, fs) + mulmod(delta_open, t.a, fs)) % fs;
        if (party == 1) {
            z_value = (z_value + mulmod(epsilon_open, delta_open, fs)) % fs;
        }
        uint64_t z_mac = (t.mac_c + mulmod(epsilon_open, t.mac_b, fs) + mulmod(delta_open, t.mac_a, fs)) % fs;
        if (party == 1) {
            z_mac = (z_mac + mulmod(mulmod(epsilon_open, delta_open, fs), mac_key, fs)) % fs;
        }
        assert(check_mac(z_value, z_mac));
        return LabeledShare(z_value, z_mac, party, &spdz2k_field_size);
    }

    LabeledShare get_zero_share() {
        return LabeledShare(0, 0, party, &spdz2k_field_size);
    }

    // 取负操作
    LabeledShare neg(const LabeledShare& x) {
        uint64_t fs = spdz2k_field_size;
        // 在模域中，-x = (fs - x) % fs
        uint64_t neg_value = (fs - x.value) % fs;
        uint64_t neg_mac = (fs - x.mac) % fs;
        return LabeledShare(neg_value, neg_mac, party, &spdz2k_field_size);
    }

    // 减法操作
    LabeledShare sub(const LabeledShare& x, const LabeledShare& y) {
        // x - y = x + (-y)
        return add(x, neg(y));
    }

    // 截断函数：在模 2^63-1 域上处理定点数截断
    LabeledShare truncate_share(const LabeledShare& x, int f) {
        uint64_t fs = spdz2k_field_size;
        
        // 直接进行截断，不使用随机掩码
        uint64_t value, mac;
        
        if (party == 1) {
            // 对于 party 1，使用特殊处理
            value = -((-x.value) >> f);
            mac = -((-x.mac) >> f);
        } else {
            // 对于其他方，直接右移
            value = x.value >> f;
            mac = x.mac >> f;
        }
        
        // 确保结果在域内
        value = (value + fs) % fs;
        mac = (mac + fs) % fs;
        
        // 验证 MAC
        assert(check_mac(value, mac));
        
        return LabeledShare(value, mac, party, &spdz2k_field_size);
    }

    // 带截断的乘法：在模 2^63-1 域上处理定点数乘法
    LabeledShare multiply_with_trunc(const LabeledShare& x, const LabeledShare& y, int f) {
        // 1. 执行标准 Beaver Triple 乘法
        LabeledShare prod = multiply(x, y);
        
        // // 2. 打印乘法结果
        // if (party == 1) {
        //     std::cout << "Before truncation: " << prod.value << " " 
        //              << FixedPointConverter::decode(prod.value % FixedPointConverter::FIELD_SIZE) << std::endl;
        // }
        
        // 3. 执行截断
        LabeledShare result = truncate_share(prod, f);
        
        // // 4. 打印截断结果
        // if (party == 1) {
        //     std::cout << "After truncation: " << result.value << " " 
        //              << FixedPointConverter::decode(result.value % FixedPointConverter::FIELD_SIZE) << std::endl;
        // 
        
        return result;
    }

    uint64_t invert(uint64_t a, const uint64_t mod = spdz2k_field_size) {
        int64_t t = 0, new_t = 1;
        int64_t r = mod, new_r = a;
        while (new_r != 0) {
            uint64_t quotient = r / new_r;
            int64_t temp_t = t;
            t = new_t;
            new_t = temp_t - quotient * new_t;
            int64_t temp_r = r;
            r = new_r;
            new_r = temp_r - quotient * new_r;
        }
        assert(r == 1);
        if (t < 0) {
            t += mod;
        }
        return static_cast<uint64_t>(t);
    }

    // 向量加法
    std::vector<LabeledShare> vector_add(const std::vector<LabeledShare>& a, const std::vector<LabeledShare>& b) {
        assert(a.size() == b.size());
        std::vector<LabeledShare> result(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            result[i] = add(a[i], b[i]);
        }
        return result;
    }

    // 矩阵乘法
    std::vector<LabeledShare> matrix_multiply(const std::vector<LabeledShare>& a, const std::vector<LabeledShare>& b, size_t m, size_t k, size_t n, int f) {
        assert(a.size() == m * k);
        assert(b.size() == k * n);

        std::vector<LabeledShare> result(m * n, get_zero_share());

        for (size_t i = 0; i < m; ++i) {
            for (size_t j = 0; j < n; ++j) {
                for (size_t p = 0; p < k; ++p) {
                    size_t a_idx = i * k + p;
                    size_t b_idx = p * n + j;
                    LabeledShare prod = multiply_with_trunc(a[a_idx], b[b_idx], f);
                    result[i * n + j] = add(result[i * n + j], prod);
                }
            }
        }

        return result;
    }

    // 张量减法
    std::vector<LabeledShare> tensor_sub(const std::vector<LabeledShare>& a, const std::vector<LabeledShare>& b) {
        assert(a.size() == b.size());
        std::vector<LabeledShare> result(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            result[i] = sub(a[i], b[i]);
        }
        return result;
    }

    // 逐元素乘法
    std::vector<LabeledShare> elementwise_multiply(const std::vector<LabeledShare>& a, const std::vector<LabeledShare>& b, int f) {
        assert(a.size() == b.size());
        std::vector<LabeledShare> result(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            result[i] = multiply_with_trunc(a[i], b[i], f);
        }
        return result;
    }

};

} // namespace emp
