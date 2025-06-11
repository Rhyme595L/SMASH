#pragma once
#include "libelgl/elgl/BLS12381Element.h"
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <cmath>
#include <mutex>
#include <atomic>
#include <iostream>
#include <mcl/bn.hpp>
#include "emp-aby/utils.h"
#include <fstream>

namespace emp {

struct BLS12381ElementHash {
    std::size_t operator()(const BLS12381Element& g) const {
        std::stringstream ss;
        g.pack(ss);
        return std::hash<std::string>()(ss.str());
    }
};

struct BSGSPrecomputation {
    uint64_t n;
    uint64_t N;
    BLS12381Element g;
    BLS12381Element g_inv_n;
    std::unordered_map<BLS12381Element, uint64_t, BLS12381ElementHash> baby_table;

    void precompute(const BLS12381Element& g_in, uint64_t N_in, uint32_t n_threads = 1);
    int64_t solve_parallel_with_pool(const BLS12381Element& y, ThreadPool* pool, uint32_t n_threads = 4) const;

    // 序列化预计算数据
    void serialize(const char* filename) {
        std::ofstream outFile(filename, std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("Cannot open file for writing");
        }

        // 写入n和N
        outFile.write(reinterpret_cast<const char*>(&n), sizeof(n));
        outFile.write(reinterpret_cast<const char*>(&N), sizeof(N));

        // 写入g和g_inv_n
        std::stringstream ss_g, ss_g_inv_n;
        g.pack(ss_g);
        g_inv_n.pack(ss_g_inv_n);
        std::string g_str = ss_g.str();
        std::string g_inv_n_str = ss_g_inv_n.str();
        
        size_t g_len = g_str.length();
        size_t g_inv_n_len = g_inv_n_str.length();
        outFile.write(reinterpret_cast<const char*>(&g_len), sizeof(g_len));
        outFile.write(g_str.c_str(), g_len);
        outFile.write(reinterpret_cast<const char*>(&g_inv_n_len), sizeof(g_inv_n_len));
        outFile.write(g_inv_n_str.c_str(), g_inv_n_len);

        // 写入baby_table
        size_t table_size = baby_table.size();
        outFile.write(reinterpret_cast<const char*>(&table_size), sizeof(table_size));
        
        for (const auto& pair : baby_table) {
            std::stringstream ss;
            pair.first.pack(ss);
            std::string key_str = ss.str();
            size_t key_len = key_str.length();
            outFile.write(reinterpret_cast<const char*>(&key_len), sizeof(key_len));
            outFile.write(key_str.c_str(), key_len);
            outFile.write(reinterpret_cast<const char*>(&pair.second), sizeof(pair.second));
        }
    }

    // 反序列化预计算数据
    void deserialize(const char* filename) {
        std::ifstream inFile(filename, std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("Cannot open file for reading");
        }

        // 读取n和N
        inFile.read(reinterpret_cast<char*>(&n), sizeof(n));
        inFile.read(reinterpret_cast<char*>(&N), sizeof(N));

        // 读取g和g_inv_n
        size_t g_len, g_inv_n_len;
        inFile.read(reinterpret_cast<char*>(&g_len), sizeof(g_len));
        std::string g_str(g_len, '\0');
        inFile.read(&g_str[0], g_len);
        std::stringstream ss_g(g_str);
        g.unpack(ss_g);

        inFile.read(reinterpret_cast<char*>(&g_inv_n_len), sizeof(g_inv_n_len));
        std::string g_inv_n_str(g_inv_n_len, '\0');
        inFile.read(&g_inv_n_str[0], g_inv_n_len);
        std::stringstream ss_g_inv_n(g_inv_n_str);
        g_inv_n.unpack(ss_g_inv_n);

        // 读取baby_table
        size_t table_size;
        inFile.read(reinterpret_cast<char*>(&table_size), sizeof(table_size));
        baby_table.clear();
        baby_table.reserve(table_size);

        for (size_t i = 0; i < table_size; ++i) {
            size_t key_len;
            inFile.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
            std::string key_str(key_len, '\0');
            inFile.read(&key_str[0], key_len);
            std::stringstream ss_key(key_str);
            BLS12381Element key;
            key.unpack(ss_key);
            
            uint64_t value;
            inFile.read(reinterpret_cast<char*>(&value), sizeof(value));
            baby_table[key] = value;
        }
    }
};

void BSGSPrecomputation::precompute(const BLS12381Element& g_in, uint64_t N_in, uint32_t n_threads) {
    g = g_in;
    N = N_in;
    n = static_cast<uint64_t>(std::ceil(std::sqrt(N)));

    // 预计算baby_table
    baby_table.clear();
    baby_table.reserve(n);

    // g^{-n}
    Fr n_fr; n_fr.setStr(std::to_string(n));
    BLS12381Element g_n = g * n_fr;
    g_inv_n = g_n.negate();

    BLS12381Element cur; // 单位元
    for (uint64_t j = 0; j < n; ++j) {
        cur.point.normalize();
        baby_table[cur] = j;
        cur = cur + g;
    }
}

int64_t BSGSPrecomputation::solve_parallel_with_pool(const BLS12381Element& y, ThreadPool* pool, uint32_t n_tasks) const {
    if (n_tasks == 0) n_tasks = 1;
    using namespace std;
    
    std::vector<std::future<int64_t>> futures;
    std::atomic<bool> found(false);
    std::atomic<int64_t> result(-1);

    for (uint32_t task_id = 0; task_id < n_tasks; ++task_id) {
        futures.push_back(pool->enqueue([this, &y, task_id, n_tasks, &found, &result]() {
            BLS12381Element giant = y;
            uint64_t start = task_id;
            // giant = y * g^{-start * n}
            if (start > 0) {
                using mcl::bn::Fr;
                Fr shift;
                shift.setStr(std::to_string(start));
                BLS12381Element shift_step = g_inv_n * shift;
                giant = giant + shift_step;
            }

            for (uint64_t i = start; i < n; i += n_tasks) {
                if (found.load(std::memory_order_relaxed)) return int64_t(-1);
                giant.point.normalize();
                auto it = baby_table.find(giant);
                if (it != baby_table.end()) {
                    uint64_t m = i * n + it->second;
                    if (m < N) {
                        result.store(m, std::memory_order_relaxed);
                        found.store(true, std::memory_order_relaxed);
                        return int64_t(m);
                    } else {
                        throw std::runtime_error("BSGS solve_parallel_with_pool: m out of range");
                    }
                }
                giant = giant + g_inv_n * n_tasks;
            }
            return int64_t(-1);
        }));
    }

    for (auto& fut : futures) {
        try {
            fut.get();
        } catch (...) {
            // 处理异常（比如超界异常），这里可以根据需要改
        }
    }

    if (result.load() >= 0) return result.load();
    throw std::runtime_error("BSGS solve_parallel_with_pool: no solution found");
}


} // namespace emp
