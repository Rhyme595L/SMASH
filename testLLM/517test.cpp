#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLYL/L2B.hpp"
#include "testLYL/B2L.hpp"
#include "testLYL/A2L_spdz2k.hpp"
#include "testLYL/L2A_spdz2k.hpp"
#include "testLLM/FixedPointConverter.h"
#include <memory>
#include <experimental/filesystem>
#include <bitset>
#include <string>
#include <cmath>

using namespace emp;
namespace fs = std::experimental::filesystem;

static double sigmoid(double x) { return 1.0/(1.0+std::exp(-x)); }
static double tanh_f(double x) { return std::tanh(x); }
const int FRACTIONAL_BITS = 16;
const int TOTAL_BITS = 24;
const int SCALE = 1 << FRACTIONAL_BITS;
const uint64_t FIELD_SIZE = 1ULL << TOTAL_BITS;
const int64_t MAX_VAL = (1LL << (TOTAL_BITS - 1)) - 1;
const int64_t MIN_VAL = -(1LL << (TOTAL_BITS - 1));
const int TABLE_SIZE = 1 << 12;  
const int DELTA_BITS = 4;
const int DELTA_TABLE_SIZE = 1 << DELTA_BITS; 
const double XMIN_SIGMOID = -16.0;
const double XMAX_SIGMOID = 16.0;
const double XMIN_TANH = -16.0;
const double XMAX_TANH = 16.0;

int num_party, party, port;
const static int threads = 8;
const int m_bits = 24; 
const int m_size = 1UL << m_bits;
const int num = 12;
const size_t tb_size = 1ULL << num; 
const int frac = 16;

std::pair<int, int> compute_table_indices(double x, double xmin, double xmax) {
    double normalized = (x - xmin) / (xmax - xmin);
    double index_float = normalized * TABLE_SIZE;
    index_float = std::max(0.0, std::min(TABLE_SIZE - 1.0, index_float));
    int base_index = static_cast<int>(index_float);
    if (base_index >= TABLE_SIZE - 1) base_index = TABLE_SIZE - 2;
    double delta = index_float - base_index;
    int delta_index = static_cast<int>(delta * DELTA_TABLE_SIZE);
    delta_index = std::min(delta_index, DELTA_TABLE_SIZE - 1);
    return {base_index, delta_index};
}

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties> <func_name>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string func_name = argv[4];
    std::string filebit = "2";
    std::string fileA = func_name + "_A";  
    std::string fileB = func_name + "_delta";  
    std::string input_file = "../../TestLLM/Input/Input-P" + std::to_string(party) + ".txt";
    double xmin = 0.0, xmax = 0.0;
    if (func_name == "sigmoid") {
        xmin = XMIN_SIGMOID;
        xmax = XMAX_SIGMOID;
    } else if (func_name == "tanh") {
        xmin = XMIN_TANH;
        xmax = XMAX_TANH;
    } else {
        std::cerr << "Unknown function: " << func_name << std::endl;
        return 1;
    }
    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc == 6) {
        const char* file = argv[5];
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
    auto io = std::make_unique<MultiIO>(party, num_party, net_config);
    auto elgl = std::make_unique<ELGL<MultiIOBase>>(num_party, io.get(), &pool, party);
    TinyMAC<MultiIOBase> tiny(elgl.get());
    SPDZ2k<MultiIOBase> spdz2k(elgl.get());
    mcl::Vint modulo = m_size;
    Fr alpha_fr_bit = alpha_init(1); 
    Fr alpha_frA = alpha_init(num);  
    Fr alpha_frB = alpha_init(num + DELTA_BITS);  
    
    std::unique_ptr<LVT<MultiIOBase>> lvt_bit, lvtA, lvtB;
    LVT<MultiIOBase>* lvt_raw_bit = nullptr;
    LVT<MultiIOBase>* lvt_rawA = nullptr;
    LVT<MultiIOBase>* lvt_rawB = nullptr;
    LVT<MultiIOBase>::initialize(filebit, lvt_raw_bit, num_party, party, io.get(), &pool, elgl.get(), alpha_fr_bit, 1, m_bits);
    lvt_bit.reset(lvt_raw_bit);
    LVT<MultiIOBase>::initialize(fileA, lvt_rawA, num_party, party, io.get(), &pool, elgl.get(), alpha_frA, num, m_bits);
    lvtA.reset(lvt_rawA);
    LVT<MultiIOBase>::initialize(fileB, lvt_rawB, num_party, party, io.get(), &pool, elgl.get(), alpha_frB, num + DELTA_BITS, m_bits);
    lvtB.reset(lvt_rawB);
    std::vector<Plaintext> x_share;
    {
        if (!fs::exists(input_file)) {
            std::cerr << "Error: input file does not exist: " << input_file << std::endl;
            return 1;
        }
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            double xval = std::stod(line);
            uint64_t xval_int = FixedPointConverter::encode(xval);

            Plaintext x;
            x.assign(xval_int);
            x_share.push_back(x);
            if (x.get_message().getUint64() > (1ULL << m_bits) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                cout << "Error value: " << x.get_message().getUint64() << ", tb_size = " << (1ULL << m_bits) << endl;
                return 1;
            }
        }
    }
    
    int x_size = x_share.size();
    Plaintext x_size_pt; x_size_pt.assign(x_size);
    elgl->serialize_sendall(x_size_pt);
    for (int i = 1; i <= num_party; i++) {
        if (i != party) {
            Plaintext x_size_pt_recv;
            elgl->deserialize_recv(x_size_pt_recv, i);
            if (x_size_pt_recv.get_message().getUint64() != x_size) {
                std::cerr << "Error: input size does not match in Party: " << party << std::endl;
                return 1;
            }
        }
    }
    std::vector<Ciphertext> x_cipher(x_size);
    std::vector<uint64_t> x_int(x_size);
    for (int i = 0; i < x_size; ++i) {
        x_cipher[i] = lvtA->global_pk.encrypt(x_share[i]);
        x_int[i] = lvtA->Reconstruct_interact(x_share[i], x_cipher[i], elgl.get(), lvtA->global_pk, lvtA->user_pk, io.get(), &pool, party, num_party, modulo).get_message().getUint64();
    }
    std::vector<double> x_real, real_fx;
    std::vector<std::pair<int, int>> table_indices;
    
    for (int i = 0; i < x_size; ++i) {
        x_real.push_back(FixedPointConverter::decode(x_int[i]));
        
        double func_result;
        if (func_name == "sigmoid") {
            func_result = sigmoid(x_real[i]);
        } else { 
            func_result = tanh_f(x_real[i]);
        }
        real_fx.push_back(func_result);
        table_indices.push_back(compute_table_indices(x_real[i], xmin, xmax));
        
        if (party == 1) {
            std::cout << "Input x[" << i << "] = " << x_real[i]
                      << ", base_idx = " << table_indices.back().first
                      << ", delta_idx = " << table_indices.back().second
                      << std::endl;
        }
    }
    std::vector<Plaintext> base_idx_share(x_size);
    std::vector<Plaintext> delta_idx_share(x_size);
    std::vector<std::vector<Ciphertext>> base_idx_cips(x_size, std::vector<Ciphertext>(num_party));
    std::vector<std::vector<Ciphertext>> delta_idx_cips(x_size, std::vector<Ciphertext>(num_party));
    
    for (int i = 0; i < x_size; ++i) {
        base_idx_share[i].assign(table_indices[i].first);
        delta_idx_share[i].assign(table_indices[i].second);
        base_idx_cips[i][party - 1] = lvtA->global_pk.encrypt(base_idx_share[i]);
        delta_idx_cips[i][party - 1] = lvtB->global_pk.encrypt(delta_idx_share[i]);
        
        elgl->serialize_sendall(base_idx_cips[i][party - 1]);
        elgl->serialize_sendall(delta_idx_cips[i][party - 1]);
        
        for (int j = 0; j < num_party; ++j) {
            if (j != party - 1) {
                elgl->deserialize_recv(base_idx_cips[i][j], j + 1);
                elgl->deserialize_recv(delta_idx_cips[i][j], j + 1);
            }
        }
    }
    std::vector<Plaintext> base_share(x_size);
    std::vector<std::vector<Ciphertext>> base_cips(x_size, std::vector<Ciphertext>(num_party));
    
    for (int i = 0; i < x_size; ++i) {
        auto [base_val, base_val_cips] = lvtA->lookup_online(base_idx_share[i], base_idx_cips[i][party-1], base_idx_cips[i]);
        base_share[i] = base_val;
        base_cips[i] = base_val_cips;
    }
    std::vector<Plaintext> delta_share(x_size);
    std::vector<std::vector<Ciphertext>> delta_cips(x_size, std::vector<Ciphertext>(num_party));
    
    for (int i = 0; i < x_size; ++i) {
        Plaintext combined_idx;
        uint64_t idx_val = (table_indices[i].first * DELTA_TABLE_SIZE) + table_indices[i].second;
        combined_idx.assign(idx_val);
        Ciphertext combined_cip = lvtB->global_pk.encrypt(combined_idx);
        std::vector<Ciphertext> combined_cips(num_party);
        combined_cips[party - 1] = combined_cip;
        
        elgl->serialize_sendall(combined_cip);
        for (int j = 0; j < num_party; ++j) {
            if (j != party - 1) {
                elgl->deserialize_recv(combined_cips[j], j + 1);
            }
        }
        auto [delta_val, delta_val_cips] = lvtB->lookup_online(combined_idx, combined_cips[party-1], combined_cips);
        delta_share[i] = delta_val;
        delta_cips[i] = delta_val_cips;
    }
    std::vector<double> interpolated_result(x_size);
    
    for (int i = 0; i < x_size; ++i) {
        Plaintext base_val = lvtA->Reconstruct(base_share[i], base_cips[i], elgl.get(), lvtA->global_pk, lvtA->user_pk, io.get(), &pool, party, num_party, modulo);
        Plaintext delta_val = lvtB->Reconstruct(delta_share[i], delta_cips[i], elgl.get(), lvtB->global_pk, lvtB->user_pk, io.get(), &pool, party, num_party, modulo);
        if (party == 1) {
            std::cout << "o_ " << base_val.get_message().getUint64() << std::endl;
            std::cout << "o_ " << delta_val.get_message().getUint64() << std::endl;
        }
        double base_float = FixedPointConverter::decode(base_val.get_message().getUint64());
        double delta_float = FixedPointConverter::decode(delta_val.get_message().getUint64());
        double fraction = static_cast<double>(table_indices[i].second) / DELTA_TABLE_SIZE;
        interpolated_result[i] = base_float + delta_float * fraction;
        
        cout << "[INTERPOLATED] f(x_" << i << ") = " << interpolated_result[i] << endl;
    }
    std::vector<double> abs_error(x_size);
    double max_error = 0, total_error = 0;
    
    for (int i = 0; i < x_size; ++i) {
        abs_error[i] = std::fabs(interpolated_result[i] - real_fx[i]);
        max_error = std::max(max_error, abs_error[i]);
        total_error += abs_error[i];
        
        cout << "[ERROR] f_true(x_" << i << ") = " << real_fx[i] 
             << ", f_interp = " << interpolated_result[i]
             << ", abs_error = " << abs_error[i] << endl;
    }
    
    cout << "\n====== Interpolation Error Summary ======\n";
    cout << "Max Error: " << max_error << endl;
    cout << "Mean Error: " << total_error / x_size << endl;

    return 0;
}

