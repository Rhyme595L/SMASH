#pragma once

#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLLM/FixedPointConverter.h"
#include <memory>
#include <atomic>
#include <vector>
#include <chrono>
#include <iostream>
#include "emp-tool/emp-tool/utils/ThreadPool.h"

namespace lvt_llm {

/**
 * Performs the offline phase of the LVT protocol
 * 
 * @param party The party ID
 * @param num_party The number of parties
 * @param port The port for network communication
 * @param func_name The function name to use for LVT
 * @param net_config Optional network configuration
 * @return A tuple containing the LVT instance, IO instance, ELGL instance, thread pool, and timing information
 */
std::tuple<
    std::unique_ptr<emp::LVT<emp::MultiIOBase>>, 
    std::unique_ptr<emp::MultiIO>, 
    std::unique_ptr<emp::ELGL<emp::MultiIOBase>>, 
    std::unique_ptr<ThreadPool>,
    float, // offline time in seconds
    float  // offline communication in MB
> 
lvt_offline_phase(
    int party, 
    int num_party, 
    int port, 
    const std::string& func_name, 
    const std::vector<std::pair<std::string, unsigned short>>& net_config = {}
) {
    using namespace emp;
    
    const int threads = 32;
    const int m_bits = 20;
    const int num = 20;
    const int tb_size = 1ULL << num;
    const int m_size = 1 << m_bits;
    
    // Setup network configuration if not provided
    std::vector<std::pair<std::string, unsigned short>> config = net_config;
    if (config.empty()) {
        for (int i = 0; i < num_party; ++i) {
            config.push_back({ "127.0.0.1", port + 4 * num_party * i });
        }
    }
    BLS12381Element::init();
    // Initialize thread pool and IO
    auto pool = std::make_unique<ThreadPool>(threads);
    auto io = std::make_unique<MultiIO>(party, num_party, config);
    auto elgl = std::make_unique<ELGL<MultiIOBase>>(num_party, io.get(), pool.get(), party);

    // Measure communication and timing
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    // Initialize LVT
    Fr alpha_fr = alpha_init(num);
    std::unique_ptr<LVT<MultiIOBase>> lvt;
    LVT<MultiIOBase>* lvt_raw = nullptr;
    cout << "dshif " <<endl;
    LVT<MultiIOBase>::initialize_batch(func_name, lvt_raw, num_party, party, io.get(), pool.get(), elgl.get(), alpha_fr, num, m_bits);
    cout << "dshif " <<endl;
    lvt.reset(lvt_raw);
    // Calculate communication and timing
    int bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    float comm_kb = float(bytes_end - bytes_start) / 1024.0 / 1024.0;
    float time_ms = std::chrono::duration<float, std::milli>(t2 - t1).count() / 1000.0;
    
    std::cout << "Offline time: " << time_ms << " s, comm: " << comm_kb << " MB" << std::endl;
    
    // 在lvt_offline_phase函数中打印一条消息，显示正在使用的端口
    std::cout << "[lvt_llm.hpp] 开始离线阶段，使用端口: " << port << ", party: " << party << std::endl;
    
    return {std::move(lvt), std::move(io), std::move(elgl), std::move(pool), time_ms, comm_kb};
}

/**
 * Performs the online phase of the LVT protocol
 * 
 * @param input_values The input float values to process
 * @param lvt The LVT instance from the offline phase
 * @param io The IO instance from the offline phase
 * @param elgl The ELGL instance from the offline phase
 * @param pool The thread pool from the offline phase
 * @param party The party ID
 * @param num_party The number of parties
 * @return A tuple containing the result vector and timing/communication information
 */
std::tuple<
    std::vector<float>,
    float, // online time in seconds
    float  // online communication in MB
>
lvt_online_phase(
    const std::vector<float>& input_values,
    emp::LVT<emp::MultiIOBase>* lvt,
    emp::MultiIO* io,  // Changed from MultiIOBase to MultiIO
    emp::ELGL<emp::MultiIOBase>* elgl,
    ThreadPool* pool,  // Changed from reference to pointer
    int party,
    int num_party
) {
    using namespace emp;
    
    const int threads = 32;
    const int m_bits = 20;
    const int m_size = 1 << m_bits;
    
    // Convert input values to Plaintext
    std::vector<Plaintext> x_share(input_values.size());
    for (size_t i = 0; i < input_values.size(); ++i) {
        if (party == 1) {
            uint64_t xval_int = FixedPointConverter::encode(input_values[i]);
            if (xval_int > (1ULL << m_bits) - 1) {
                std::cout << "Warning: input value exceeds table size: " << xval_int << std::endl;
                xval_int = (1ULL << m_bits) - 1;
            }
            x_share[i].assign(xval_int);
        } else {
            x_share[i].assign("0");
        }
    }
    
    int x_size = x_share.size();
    
    // Synchronize input size across parties
    Plaintext x_size_pt; x_size_pt.assign(x_size);
    elgl->serialize_sendall(x_size_pt);
    for (int i = 1; i <= num_party; i++) {
        if (i != party) {
            Plaintext x_size_pt_recv;
            elgl->deserialize_recv(x_size_pt_recv, i);
            if (int(x_size_pt_recv.get_message().getUint64()) != x_size) {
                std::cerr << "Error: input size does not match in Party: " << party << std::endl;
                throw std::runtime_error("Input size mismatch between parties");
            }
        }
    }
    
    // Generate ciphertexts in parallel
    std::vector<Ciphertext> x_cipher(x_size);
    size_t block_size = (x_size + threads - 1) / threads;
    std::vector<std::future<void>> futures;
    
    for (size_t t = 0; t < threads && t * block_size < x_size; t++) {
        size_t start = t * block_size;
        size_t end = std::min(static_cast<size_t>(x_size), start + block_size);
        
        futures.push_back(pool->enqueue([&, start, end]() {
            for (size_t i = start; i < end; i++) {
                x_cipher[i] = lvt->global_pk.encrypt(x_share[i]);
            }
        }));
    }
    
    // Wait for all encryption to complete
    for (auto& fut : futures) fut.get();
    
    // Measure communication and timing for online phase
    int bytes_start = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();
    
    // Perform the actual LVT lookup
    auto [out, out_ciphers] = lvt->lookup_online_(x_share, x_cipher);
    
    int bytes_end = io->get_total_bytes_sent();
    auto t4 = std::chrono::high_resolution_clock::now();
    float comm_kb = float(bytes_end - bytes_start) / 1024.0 / 1024.0;
    float time_ms = std::chrono::duration<float, std::milli>(t4 - t3).count() / 1000.0;
    std::cout << "Online time: " << time_ms << " s, comm: " << comm_kb << " MB" << std::endl;
    
    // Process results
    Plaintext value_field = Plaintext(m_size);
    
    // Process and verify results in parallel
    std::vector<float> out_sum_float(x_size);
    std::vector<Plaintext> out_sum(x_size);
    
    // First phase: all parties exchange shares and compute sum
    for (int i = 0; i < x_size; ++i) {
        out_sum[i] = out[i];
    }
    
    // Serialize local shares into a string stream
    std::stringstream shares_stream;
    for (int i = 0; i < x_size; ++i) {
        out[i].pack(shares_stream);
    }
    
    // Get serialized data
    std::string shares_str = shares_stream.str();
    
    // Send shares to other parties in parallel
    std::vector<std::future<void>> send_futures;
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            send_futures.push_back(pool->enqueue([io, j, &shares_str]() {
                io->send_data(j, shares_str.data(), shares_str.size());
            }));
        }
    }
    
    // Receive and process shares from other parties in parallel
    std::vector<std::future<void>> recv_futures;
    std::mutex out_sum_mutex;
    
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            recv_futures.push_back(pool->enqueue([&out_sum, &out_sum_mutex, io, j, x_size, &value_field]() {
                // Receive data
                int data_len = 0;
                char* recv_data = (char*)io->recv_data(j, data_len);
                
                if (recv_data) {
                    // Deserialize received data
                    std::stringstream ss;
                    ss.write(recv_data, data_len);
                    free(recv_data);
                    
                    // Unpack and accumulate
                    std::vector<Plaintext> recv_shares(x_size);
                    for (int i = 0; i < x_size; ++i) {
                        recv_shares[i].unpack(ss);
                        
                        // Thread-safe accumulation
                        std::lock_guard<std::mutex> lock(out_sum_mutex);
                        out_sum[i] += recv_shares[i];
                        out_sum[i] = out_sum[i] % value_field;
                    }
                }
            }));
        }
    }
    
    // Wait for all sends and receives to complete
    for (auto& fut : send_futures) fut.get();
    for (auto& fut : recv_futures) fut.get();
    
    // Second phase: verify consistency of results across parties
    // Serialize results
    std::stringstream result_stream;
    for (int i = 0; i < x_size; ++i) {
        out_sum[i].pack(result_stream);
    }
    
    // Get serialized data
    std::string result_str = result_stream.str();
    
    // Send results to other parties in parallel
    send_futures.clear();
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            send_futures.push_back(pool->enqueue([io, j, &result_str]() {
                io->send_data(j, result_str.data(), result_str.size());
            }));
        }
    }
    
    // Receive and verify results
    recv_futures.clear();
    std::atomic<bool> results_match(true);
    
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            recv_futures.push_back(pool->enqueue([&results_match, io, j, x_size, &out_sum]() {
                // Receive data
                int data_len = 0;
                char* recv_data = (char*)io->recv_data(j, data_len);
                
                if (recv_data) {
                    // Deserialize received data
                    std::stringstream ss;
                    ss.write(recv_data, data_len);
                    free(recv_data);
                    
                    // Unpack and verify
                    std::vector<Plaintext> recv_results(x_size);
                    for (int i = 0; i < x_size; ++i) {
                        recv_results[i].unpack(ss);
                        
                        if (recv_results[i].get_message().getUint64() != out_sum[i].get_message().getUint64()) {
                            results_match = false;
                        }
                    }
                }
            }));
        }
    }
    
    // Wait for all sends and receives to complete
    for (auto& fut : send_futures) fut.get();
    for (auto& fut : recv_futures) fut.get();
    
    if (!results_match) {
        std::cerr << "Error: Results don't match across parties" << std::endl;
    }
    
    // Convert results to float in parallel
    std::vector<std::future<void>> convert_futures;
    block_size = (x_size + threads - 1) / threads;
    
    for (size_t t = 0; t < threads && t * block_size < x_size; t++) {
        size_t start = t * block_size;
        size_t end = std::min(static_cast<size_t>(x_size), start + block_size);
        
        convert_futures.push_back(pool->enqueue([&out_sum_float, &out_sum, start, end]() {
            for (size_t i = start; i < end; i++) {
                out_sum_float[i] = FixedPointConverter::decode(out_sum[i].get_message().getUint64());
            }
        }));
    }
    
    // Wait for all conversions to complete
    for (auto& fut : convert_futures) fut.get();
    
    return {out_sum_float, time_ms, comm_kb};
}

} // namespace lvt_llm
