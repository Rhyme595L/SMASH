#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLLM/FixedPointConverter.h"
#include <memory>
#include <atomic>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string_view>
using namespace emp;

int party, port;
const static int threads = 32;
int num_party;
int m_bits = 24; 
int m_size = 1 << m_bits; 
int num = 24;
int tb_size = 1ULL << num; 
std::vector<Plaintext> parallel_load_input(const std::string& input_file, int party, int m_bits, ThreadPool& pool) {
    if (!fs::exists(input_file)) {
        std::cerr << "Error: input file does not exist: " << input_file << std::endl;
        return {};
    }
    std::vector<std::string> lines;
    {
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            lines.push_back(line);
        }
    }
    size_t line_count = lines.size();
    std::vector<Plaintext> x_share(line_count);
    std::vector<std::future<void>> futures;
    size_t block_size = (line_count + threads - 1) / threads;
    
    for (size_t t = 0; t < threads && t * block_size < line_count; t++) {
        size_t start = t * block_size;
        size_t end = std::min(line_count, start + block_size);
        
        futures.push_back(pool.enqueue([&, start, end, party, m_bits]() {
            for (size_t i = start; i < end; i++) {
                if (party == 1) {
                    float xval = std::stod(lines[i]);
                    uint64_t xval_int = FixedPointConverter::encode(xval);
                    
                    if (xval_int > (1ULL << m_bits) - 1) {
                        std::cout << "Warning: input value exceeds table size: " << xval_int << std::endl;
                        xval_int = (1ULL << m_bits) - 1;
                    }
                    x_share[i].assign(xval_int);
                } else {
                    x_share[i].assign("0");
                }
            }
        }));
    }
    for (auto& fut : futures) fut.get();
    return x_share;
}
std::vector<Ciphertext> parallel_encrypt(const std::vector<Plaintext>& x_share, 
                                        const ELGL_PK& global_pk, 
                                        ThreadPool& pool) {
    size_t x_size = x_share.size();
    std::vector<Ciphertext> x_cipher(x_size);
    
    std::vector<std::future<void>> futures;
    size_t block_size = (x_size + threads - 1) / threads;
    
    for (size_t t = 0; t < threads && t * block_size < x_size; t++) {
        size_t start = t * block_size;
        size_t end = std::min(x_size, start + block_size);
        
        futures.push_back(pool.enqueue([&, start, end]() {
            for (size_t i = start; i < end; i++) {
                x_cipher[i] = global_pk.encrypt(x_share[i]);
            }
        }));
    }
    for (auto& fut : futures) fut.get();
    
    return x_cipher;
}
std::vector<float> parallel_process_results(std::vector<Plaintext>& out, 
                                           ELGL<MultiIOBase>* elgl, 
                                           MPIOChannel<MultiIOBase>* io,
                                           int party, 
                                           int num_party, 
                                           const Plaintext& value_field,
                                           ThreadPool& pool) {
    size_t x_size = out.size();
    std::vector<float> out_sum_float(x_size);
    std::vector<Plaintext> out_sum(x_size);
    for (int i = 0; i < x_size; ++i) {
        out_sum[i] = out[i];
    }
    std::stringstream shares_stream;
    for (int i = 0; i < x_size; ++i) {
        out[i].pack(shares_stream);
    }
    
    std::string shares_str = shares_stream.str();
    const char* shares_data = shares_str.c_str();
    int shares_size = shares_str.size();
    
    std::vector<std::future<void>> send_futures;
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            send_futures.push_back(pool.enqueue([io, j, shares_data, shares_size]() {
                io->send_data(j, shares_data, shares_size);
            }));
        }
    }
    
    std::vector<std::future<void>> recv_futures;
    std::mutex out_sum_mutex;
    
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            recv_futures.push_back(pool.enqueue([&out_sum, &out_sum_mutex, io, j, x_size, &value_field]() {
                int data_len = 0;
                void* recv_data = io->recv_data(j, data_len);
                
                if (recv_data) {
                    std::stringstream ss;
                    ss.write(static_cast<char*>(recv_data), data_len);
                    free(recv_data);
                    
                    std::vector<Plaintext> recv_shares(x_size);
                    for (int i = 0; i < x_size; ++i) {
                        recv_shares[i].unpack(ss);
                        
                        std::lock_guard<std::mutex> lock(out_sum_mutex);
                        out_sum[i] += recv_shares[i];
                        out_sum[i] = out_sum[i] % value_field;
                    }
                }
            }));
        }
    }
    
    for (auto& fut : send_futures) fut.get();
    for (auto& fut : recv_futures) fut.get();
    
    std::stringstream result_stream;
    for (int i = 0; i < x_size; ++i) {
        out_sum[i].pack(result_stream);
    }
    
    std::string result_str = result_stream.str();
    const char* result_data = result_str.c_str();
    int result_size = result_str.size();
    
    send_futures.clear();
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            send_futures.push_back(pool.enqueue([io, j, result_data, result_size]() {
                io->send_data(j, result_data, result_size);
            }));
        }
    }
    
    recv_futures.clear();
    std::atomic<bool> results_match(true);
    
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            recv_futures.push_back(pool.enqueue([&results_match, io, j, x_size, &out_sum]() {
                int data_len = 0;
                void* recv_data = io->recv_data(j, data_len);
                
                if (recv_data) {
                    std::stringstream ss;
                    ss.write(static_cast<char*>(recv_data), data_len);
                    free(recv_data);
                    
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
    
    for (auto& fut : send_futures) fut.get();
    for (auto& fut : recv_futures) fut.get();
    
    if (!results_match) {
        std::cerr << "Error: Results don't match across parties" << std::endl;
    }
    
    std::vector<std::future<void>> convert_futures;
    size_t block_size = (x_size + threads - 1) / threads;
    
    for (size_t t = 0; t < threads && t * block_size < x_size; t++) {
        size_t start = t * block_size;
        size_t end = std::min(x_size, start + block_size);
        
        convert_futures.push_back(pool.enqueue([&out_sum_float, &out_sum, start, end]() {
            for (size_t i = start; i < end; i++) {
                out_sum_float[i] = FixedPointConverter::decode(out_sum[i].get_message().getUint64());
            }
        }));
    }
    
    for (auto& fut : convert_futures) fut.get();
    
    return out_sum_float;
}

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties> <func_name> [file_format]" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string func_name = argv[4];
    
    std::string file_format = "txt";
    if (argc >= 6) {
        file_format = argv[5];
    }
    bool use_binary = (file_format == "bin");

    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc >= 7) {
        const char* file = argv[6];
        FILE* f = fopen(file, "r");
        for (int i = 0; i < num_party; ++i) {
            char* c = (char*)malloc(15 * sizeof(char));
            uint p;
            fscanf(f, "%s %d\tb_size", c, &p);
            net_config.push_back(std::make_pair(std::string(c), p));
            fflush(f);
        }
        fclose(f);
    } else {
        for (int i = 0; i < num_party; ++i) {
            net_config.push_back({ "127.0.0.1", port + 4 * num_party * i });
        }
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    Fr alpha_fr = alpha_init(num);
   
    cout << "Generating new state..." << endl;
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, func_name, alpha_fr, num, m_bits);
    cout << "Generate shares finished" << endl;
    lvt->generate_shares_(lvt->lut_share, lvt->rotation, lvt->table);
    
    Plaintext tb_field = Plaintext(tb_size);
    Plaintext value_field = Plaintext(m_size);

    int bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    float comm_kb = float(bytes_end - bytes_start) / 1024.0 / 1024.0;
    float time_ms = std::chrono::duration<float, std::milli>(t2 - t1).count() / 1000.0;
    cout << "Offline time: " << time_ms << " s, comm: " << comm_kb << " MB" << std::endl;

    std::string input_base = "../Input/Input-P";
    std::string input_file = use_binary ? input_base + ".bin" : input_base + ".txt";
    
    std::vector<Plaintext> x_share;
    int x_size = 0;
    
    if (use_binary) {
        int fd = open(input_file.c_str(), O_RDONLY);
        if (fd < 0) {
            std::cerr << "Error: Cannot open binary input file: " << input_file << std::endl;
            return 1;
        }
        struct stat sb;
        if (fstat(fd, &sb) < 0) {
            std::cerr << "Error: fstat failed on input file: " << input_file << std::endl;
            close(fd);
            return 1;
        }
        
        x_size = (sb.st_size) / sizeof(float);
        std::cout << "Total elements to read: " << x_size << std::endl;
        
        x_share.clear();
        x_share.resize(x_size);
        
        void* mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapped == MAP_FAILED) {
            std::cerr << "Error: mmap failed on input file: " << input_file << std::endl;
            close(fd);
            return 1;
        }
        
        float* values = reinterpret_cast<float*>(mapped);
        
        const size_t BATCH_SIZE = 10000;
        std::vector<std::future<void>> futures;
        
        for (size_t batch_start = 0; batch_start < x_size; batch_start += BATCH_SIZE) {
            size_t batch_end = std::min(batch_start + BATCH_SIZE, static_cast<size_t>(x_size));
            futures.push_back(pool.enqueue([&, batch_start, batch_end, values]() {
                for (size_t i = batch_start; i < batch_end; i++) {
                    if (party == 1) {
                        uint64_t xval_int = FixedPointConverter::encode(values[i]);
                        if (xval_int > (1ULL << m_bits) - 1) {
                            xval_int = (1ULL << m_bits) - 1;
                        }
                        x_share[i].assign(xval_int);
                    } else {
                        x_share[i].assign("0");
                    }
                }
            }));
        }
        
        for (auto& fut : futures) fut.get();
        
        munmap(mapped, sb.st_size);
        close(fd);
        std::cout << "Successfully read " << x_size << " values from binary file" << std::endl;
    } else {
        x_share = parallel_load_input(input_file, party, m_bits, pool);
        if (x_share.empty()) {
            return 1;
        }
        x_size = x_share.size();
    }
    
    Plaintext x_size_pt; x_size_pt.assign(x_size);
    elgl->serialize_sendall(x_size_pt);
    for (int i = 1; i <= num_party; i++) {
        if (i != party) {
            Plaintext x_size_pt_recv;
            elgl->deserialize_recv(x_size_pt_recv, i);
            if (int(x_size_pt_recv.get_message().getUint64()) != x_size) {
                std::cerr << "Error: input size does not match in Party: " << party << std::endl;
                return 1;
            }
        }
    }
    
    std::vector<Ciphertext> x_cipher = parallel_encrypt(x_share, lvt->global_pk, pool);

    int bytes_start1 = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<Ciphertext>> x_ciphers(x_size);
    auto [out, out_ciphers] = lvt->lookup_online_batch(x_share, x_cipher, x_ciphers);

    int bytes_end1 = io->get_total_bytes_sent();
    auto t4 = std::chrono::high_resolution_clock::now();
    float comm_kb1 = float(bytes_end1 - bytes_start1) / 1024.0 / 1024.0;
    float time_ms1 = std::chrono::duration<float, std::milli>(t4 - t3).count() / 1000.0;
    cout << "Online time: " << time_ms1 << " s, comm: " << comm_kb1 << " MB" << std::endl;

    std::vector<float> out_sum_float = parallel_process_results(out, elgl, io, party, num_party, value_field, pool);

    if (party == 1) {
        std::string output_base = "../Output/Output";
        std::string output_file = use_binary ? output_base + ".bin" : output_base + ".txt";
        
        if (use_binary) {
            std::ofstream outfile(output_file, std::ios::binary | std::ios::trunc);
            if (!outfile) {
                std::cerr << "Error: Cannot open binary output file: " << output_file << std::endl;
                return 1;
            }
            int32_t length = static_cast<int32_t>(out_sum_float.size());
            outfile.write(reinterpret_cast<const char*>(&length), sizeof(int32_t));
            if (!out_sum_float.empty()) {
                outfile.write(reinterpret_cast<const char*>(out_sum_float.data()), out_sum_float.size() * sizeof(float));
            }
            std::cout << "Wrote " << out_sum_float.size() << " values to binary file" << std::endl;
        } else {
            std::stringstream output_content;
            for (int i = 0; i < x_size; ++i) {
                output_content << out_sum_float[i] << std::endl;
            }
            
            std::ofstream out_file(output_file, std::ios::trunc);
            if (!out_file) {
                std::cerr << "Error: Cannot open text output file: " << output_file << std::endl;
                return 1;
            }
            out_file << output_content.str();
        }
    }

    return 0;
}
