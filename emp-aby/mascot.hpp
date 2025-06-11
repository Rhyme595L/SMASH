#pragma once

#include "elgl_interface.hpp"
#include <vector>
#include <random>
#include <chrono>
#include <cassert>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <map>
#include <mcl/vint.hpp>
#include <mcl/fp.hpp>

const mcl::Vint field_size("52435875175126190479447740508185965837690552500527637822603658699938581184512");
// const mcl::Vint field_size_2("340282366920938463463374607431768211297");
// const mcl::Vint field_size(to_string(1ULL << 32));
namespace emp {

template <typename IO>
class MASCOT {
public:
    ELGL<IO>* elgl;
    int party;
    int num_parties;
    std::mutex mtx;
    std::condition_variable cv;

    // 用于随机数生成
    std::mt19937_64 rng;

    // MAC 密钥（每方都有一个密钥）
    mcl::Vint mac_key;

    // 带标签的共享值类型，包含 MAC
    struct LabeledShare {
        mcl::Vint value;
        mcl::Vint mac;
        int owner;
        const mcl::Vint* field_size_ptr; // 指向MASCOT的field_size

        LabeledShare() : value(0), mac(0), owner(0), field_size_ptr(nullptr) {}
        LabeledShare(const mcl::Vint& v, const mcl::Vint& m, int o, const mcl::Vint* fs) : value(v), mac(m), owner(o), field_size_ptr(fs) {}

        void pack(std::stringstream& ss) const {
            ss << value.getStr() << " " << mac.getStr() << " " << owner << " ";
        }

        void unpack(std::stringstream& ss) {
            std::string s1, s2;
            ss >> s1 >> s2 >> owner;
            value.setStr(s1);
            mac.setStr(s2);
        }

        // 加法重载
        LabeledShare operator+(const LabeledShare& rhs) const {
            mcl::Vint fs = field_size;
            mcl::Vint v = ((value + rhs.value) % fs + fs) % fs;
            mcl::Vint m = ((mac + rhs.mac) % fs + fs) % fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
        // 标量乘法重载
        LabeledShare operator*(const mcl::Vint& scalar) const {
            mcl::Vint fs = field_size;
            mcl::Vint s = scalar % fs;
            mcl::Vint v = ((value * s) % fs + fs) % fs;
            mcl::Vint m = ((mac * s) % fs + fs) % fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
    };

    // 三元组类型，包含 MAC
    struct Triple {
        mcl::Vint a, b, c, mac_a, mac_b, mac_c;
        Triple() : a(0), b(0), c(0), mac_a(0), mac_b(0), mac_c(0) {}
        Triple(const mcl::Vint& a, const mcl::Vint& b, const mcl::Vint& c, const mcl::Vint& mac_a, const mcl::Vint& mac_b, const mcl::Vint& mac_c)
            : a(a), b(b), c(c), mac_a(mac_a), mac_b(mac_b), mac_c(mac_c) {}

        void pack(std::stringstream& ss) const {
            ss << a.getStr() << " " << b.getStr() << " " << c.getStr() << " "
               << mac_a.getStr() << " " << mac_b.getStr() << " " << mac_c.getStr() << " ";
        }

        void unpack(std::stringstream& ss) {
            std::string sa, sb, sc, sma, smb, smc;
            ss >> sa >> sb >> sc >> sma >> smb >> smc;
            a.setStr(sa); b.setStr(sb); c.setStr(sc);
            mac_a.setStr(sma); mac_b.setStr(smb); mac_c.setStr(smc);
        }
    };

    // 用于存储三元组
    std::vector<Triple> triples_pool;

    // 预计算三元组
    void precompute_triples(size_t num_triples) {
        for (size_t i = 0; i < num_triples; i++) {
            generate_triple();
        }
    }

    // 生成单个三元组
    void generate_triple() {
        mcl::Vint a_local, b_local;
        a_local.setRand(field_size); a_local %= field_size;
        b_local.setRand(field_size); b_local %= field_size;
        std::stringstream ss;
        ss << a_local.getStr() << " " << b_local.getStr() << " ";
        elgl->serialize_sendall_with_tag(ss, 2000 * party + party);
        mcl::Vint a_full = a_local, b_full = b_local;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 2000 * i + i);
                std::string sa, sb;
                mcl::Vint other_a, other_b;
                ss_recv >> sa >> sb;
                other_a.setStr(sa); other_b.setStr(sb);
                a_full += other_a; b_full += other_b;
            }
        }
        mcl::Vint c_full = a_full * b_full % field_size;
        mcl::Vint c_local = (party == 1) ? c_full : mcl::Vint(0);
        mcl::Vint mac_a = a_local * mac_key % field_size;
        mcl::Vint mac_b = b_local * mac_key % field_size;
        mcl::Vint mac_c = c_local * mac_key % field_size;
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

    // 检查 MAC 的有效性
    bool check_mac(const mcl::Vint& value, const mcl::Vint& mac) const {
        return mac == (value * mac_key % field_size + field_size) % field_size;
    }

    // 通信辅助函数：发送一个值和其 MAC 给特定方 dst
    void send_value_and_mac(const mcl::Vint& value, const mcl::Vint& mac, int dst) {
        std::stringstream ss;
        ss << value.getStr() << " " << mac.getStr() << " ";
        elgl->serialize_send_with_tag(ss, dst, 5000 * dst + party);
    }

    // 通信辅助函数：从src接收一个值和其 MAC
    std::pair<mcl::Vint, mcl::Vint> recv_value_and_mac(int src) {
        std::stringstream ss;
        elgl->deserialize_recv_with_tag(ss, src, 5000 * party + src);
        std::string s1, s2;
        mcl::Vint value, mac;
        ss >> s1 >> s2;
        value.setStr(s1); mac.setStr(s2);
        std::cout << party << " recv_value_and_mac: " << value.getStr() << std::endl;
        return {value, mac};
    }

    // 获取零分享
    LabeledShare get_zero_share() {
        mcl::Vint zero(0);
        return LabeledShare(zero, zero, party, &field_size);
    }

    MASCOT(ELGL<IO>* elgl_instance) : elgl(elgl_instance) {
        party = elgl->party;
        num_parties = elgl->num_party;

        // 初始化随机数生成器
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count() + party;
        rng.seed(seed);

        // 全局MAC密钥协商
        mcl::Vint local_mac_key; local_mac_key.setRand(field_size); local_mac_key %= field_size;
        {
            std::stringstream ss;
            ss << local_mac_key.getStr() << " ";
            elgl->serialize_sendall_with_tag(ss, 3000 * party + party);
        }
        mcl::Vint global_mac_key = local_mac_key;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 3000 * i + i);
                std::string s;
                ss_recv >> s;
                mcl::Vint other_key; other_key.setStr(s);
                global_mac_key += other_key;
            }
        }
        mac_key = global_mac_key % field_size;

        // 预计算一些三元组
        precompute_triples(20);
    }

    ~MASCOT() {}

    // 每个参与方都调用，输入自己的xi，返回本地最终share
    LabeledShare distributed_share(const mcl::Vint& xi) {
        std::vector<mcl::Vint> shares(num_parties, mcl::Vint(0));
        mcl::Vint remain = xi % field_size;
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            mcl::Vint tmp; tmp.setRand(field_size); tmp %= field_size;
            shares[i-1] = tmp;
            remain = (remain - tmp) % field_size;
        }
        shares[party-1] = remain;
        std::vector<mcl::Vint> received(num_parties, mcl::Vint(0));
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            if (party < i) {
                std::stringstream ss;
                mcl::Vint mac = shares[i-1] * mac_key % field_size;
                ss << shares[i-1].getStr() << " " << mac.getStr() << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                std::string sshare, smac;
                mcl::Vint share, mac2;
                ss_recv >> sshare >> smac;
                share.setStr(sshare); mac2.setStr(smac);
                assert(check_mac(share, mac2));
                received[i-1] = share % field_size;
            } else {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                std::string sshare, smac;
                mcl::Vint share, mac2;
                ss_recv >> sshare >> smac;
                share.setStr(sshare); mac2.setStr(smac);
                assert(check_mac(share, mac2));
                received[i-1] = share % field_size;
                std::stringstream ss;
                mcl::Vint mac = shares[i-1] * mac_key % field_size;
                ss << shares[i-1].getStr() << " " << mac.getStr() << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
            }
        }
        received[party-1] = remain;
        mcl::Vint local_share = 0;
        for (int i = 0; i < num_parties; ++i) {
            local_share = (local_share + received[i]) % field_size;
        }
        local_share = (local_share + field_size) % field_size;
        mcl::Vint mac = local_share * mac_key % field_size;
        mac = (mac + field_size) % field_size;
        return LabeledShare(local_share, mac, party, &field_size);
    }

    // 重构秘密，验证 MAC
    mcl::Vint reconstruct(const LabeledShare& share) {
        std::stringstream ss;
        share.pack(ss);
        elgl->serialize_sendall_with_tag(ss, 1000 * party + party);
        mcl::Vint result = share.value % field_size;
        for (int i = 1; i <= num_parties; i++) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 1000 * i + i);
                LabeledShare other_share;
                other_share.unpack(ss_recv);
                other_share.field_size_ptr = &field_size;
                assert(check_mac(other_share.value, other_share.mac));
                mcl::Vint v = other_share.value % field_size;
                result = (result + v) % field_size;
            }
        }
        return result;
    }

    // 加法操作，包括 MAC
    LabeledShare add(const LabeledShare& x, const LabeledShare& y) {
        return x + y;
    }

    // 标量乘法，包括 MAC
    LabeledShare mul_const(const LabeledShare& x, const mcl::Vint& scalar) {
        return x * scalar;
    }

    // 乘法操作，包括 MAC
    LabeledShare multiply(const LabeledShare& x, const LabeledShare& y) {
        Triple t = get_triple();
        
        // 计算epsilon = x - a 和 delta = y - b，并进行模运算
        mcl::Vint epsilon = (x.value - t.a) % field_size;
        epsilon = (epsilon + field_size) % field_size; // 确保非负
        mcl::Vint delta = (y.value - t.b) % field_size;
        delta = (delta + field_size) % field_size;

        // 构造epsilon和delta的带MAC共享
        LabeledShare eps_share(
            epsilon, 
            (x.mac - t.mac_a + field_size) % field_size, // MAC差值模运算
            party, 
            &field_size
        );
        
        LabeledShare del_share(
            delta,
            (y.mac - t.mac_b + field_size) % field_size,
            party,
            &field_size
        );

        // 重构epsilon和delta（明文值）
        mcl::Vint epsilon_open = reconstruct(eps_share);
        mcl::Vint delta_open = reconstruct(del_share);

        // 计算z = c + epsilon*b + delta*a + epsilon*delta（仅party1添加交叉项）
        mcl::Vint z_value = (t.c + 
                          (epsilon_open * t.b) % field_size + 
                          (delta_open * t.a) % field_size) % field_size;
        
        if (party == 1) {
            z_value = (z_value + (epsilon_open * delta_open) % field_size) % field_size;
        }
        z_value = (z_value + field_size) % field_size; // 最终取模

        // 计算MAC：z_mac = mac_c + epsilon*mac_b + delta*mac_a + epsilon*delta*mac_key
        mcl::Vint z_mac = (t.mac_c + 
                        (epsilon_open * t.mac_b) % field_size + 
                        (delta_open * t.mac_a) % field_size) % field_size;
        
        if (party == 1) {
            z_mac = (z_mac + (epsilon_open * delta_open * mac_key) % field_size) % field_size;
        }
        z_mac = (z_mac + field_size) % field_size;

        // 验证本地z_value的MAC
        assert(check_mac(z_value, z_mac));

        return LabeledShare(z_value, z_mac, party, &field_size);
    }

    void print_raw_values(const LabeledShare& share) {
        std::cout << "[LOG] shared_x.value (raw): " << share.value.getStr() << std::endl;
        std::cout << "[LOG] shared_r.value (raw): " << share.value.getStr() << std::endl;
    }

    LabeledShare truncate_share(const LabeledShare& x, int f) {
        mcl::Vint fs = field_size;
        
        // 1. 生成随机掩码
        mcl::Vint r; r.setRand(fs >> 1);  // 确保 r 不会太大
        mcl::Vint r_hi = r >> f;

        // 2. 生成共享
        LabeledShare share_r = distributed_share(r);
        LabeledShare share_r_hi = distributed_share(r_hi);
        
        // 3. 掩码操作
        LabeledShare masked = add(x, share_r);
        
        // 4. 公开值
        mcl::Vint z = reconstruct(masked);
        
        // 5. 正确处理有符号数
        bool is_negative = z >= (fs >> 1);
        mcl::Vint z_abs = is_negative ? fs - z : z;
        mcl::Vint z_trunc = z_abs >> f;
        if (is_negative) {
            z_trunc = fs - z_trunc;
        }
        
        // 6. 计算最终结果
        mcl::Vint result_value = (z_trunc - share_r_hi.value) % fs;
        if (result_value < 0) result_value += fs;
        
        mcl::Vint result_mac = (result_value * mac_key) % fs;
        
        return LabeledShare(result_value, result_mac, party, &field_size);
    }

    LabeledShare multiply_with_trunc(const LabeledShare& x, const LabeledShare& y, int f) {
        Triple t = get_triple();

        // Step 1: Calculate ε = x - a and δ = y - b with proper modulo
        mcl::Vint eps = (x.value - t.a) % field_size;
        eps = (eps + field_size) % field_size;
        mcl::Vint del = (y.value - t.b) % field_size;
        del = (del + field_size) % field_size;

        // Step 2: Construct shares for ε and δ
        LabeledShare eps_share(
            eps,
            ((x.mac - t.mac_a) % field_size + field_size) % field_size,
            party,
            &field_size
        );
        LabeledShare del_share(
            del,
            ((y.mac - t.mac_b) % field_size + field_size) % field_size,
            party,
            &field_size
        );

        // Step 3: Reconstruct ε and δ
        mcl::Vint eps_open = reconstruct(eps_share);
        mcl::Vint del_open = reconstruct(del_share);

        LabeledShare tmp;
        // Step 4: Calculate z = c + ε·b + δ·a + ε·δ with proper modulo at each step
        if (party == 1) {
            tmp = LabeledShare(eps_open * t.b + del_open * t.a + eps_open * del_open, eps_open * t.mac_b + del_open * t.mac_a + eps_open * del_open * mac_key, party, &field_size);
            tmp = truncate_share(tmp, f);
        }
        else {
            tmp = LabeledShare(eps_open * t.b + del_open * t.a, eps_open * t.mac_b + del_open * t.mac_a, party, &field_size);
            tmp = truncate_share(tmp, f);
        }

        mcl::Vint z_value = t.c + tmp.value;
        z_value = (z_value + field_size) % field_size;
        mcl::Vint z_mac = t.mac_c + tmp.mac;
        z_mac = (z_mac + field_size) % field_size;

        // Create the multiplication result share
        LabeledShare mult_result(z_value, z_mac, party, &field_size);

        // Truncate the result - critical for fixed-point math
        return mult_result;
    }


};

} // namespace emp