#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLLM/FixedPointConverter.h"
#include <memory>

using namespace emp;

int party, port;
const static int threads = 32;
int num_party;
int m_bits = 22; 
int m_size = 1 << m_bits; 
int num = 22;
int tb_size = 1ULL << num; 

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties> <func_name>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string func_name = argv[4];

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
    Fr alpha_fr = alpha_init(num);
    std::unique_ptr<LVT<MultiIOBase>> lvt;
    LVT<MultiIOBase>* lvt_raw = nullptr;

    LVT<MultiIOBase>::initialize(func_name, lvt_raw, num_party, party, io.get(), &pool, elgl.get(), alpha_fr, num, m_bits);
    lvt.reset(lvt_raw);

    mpz_class fd = m_size;

    std::vector<Plaintext> x_share;
    std::string input_file = "../Input/Input-P.txt";
    {
        if (!fs::exists(input_file)) {
            std::cerr << "Error: input file does not exist: " << input_file << std::endl;
            return 1;
        }
        std::ifstream in_file(input_file);
        std::string line;
        if (party == 1) {
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
        else {
            while (std::getline(in_file, line)) {
                double xval = std::stod(line);
                uint64_t xval_int = FixedPointConverter::encode(xval);

                Plaintext x;
                x.assign("0");
                x_share.push_back(x);
                if (x.get_message().getUint64() > (1ULL << m_bits) - 1) {
                    std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                    cout << "Error value: " << x.get_message().getUint64() << ", tb_size = " << (1ULL << m_bits) << endl;
                    return 1;
                }
            }
        }
    }
    int x_size = x_share.size();
    Plaintext x_size_pt; x_size_pt.assign(x_size);
    elgl.get()->serialize_sendall(x_size_pt);
    for (int i = 1; i <= num_party; i++) {
        if (i != party) {
            Plaintext x_size_pt_recv;
            elgl.get()->deserialize_recv(x_size_pt_recv, i);
            if (int(x_size_pt_recv.get_message().getUint64()) != x_size) {
                std::cerr << "Error: input size does not match in Party: " << party << std::endl;
                return 1;
            }
        }
    }
    Plaintext tb_field = Plaintext(tb_size);
    Plaintext value_field = Plaintext(m_size);

    for (int i = 0; i < x_size; ++i) {
        Plaintext x_sum = x_share[i];
        elgl.get()->serialize_sendall(x_sum);
        for (int i = 1; i <= num_party; i++) {
            if (i != party) {
                Plaintext x_recv;
                elgl.get()->deserialize_recv(x_recv, i);
                x_sum += x_recv;
                x_sum = x_sum % tb_field;
            }
        }
        uint64_t table_x = lvt->table[x_sum.get_message().getUint64()];
        Plaintext table_pt = Plaintext(table_x);
        elgl.get()->serialize_sendall(table_pt);
        for (int i = 1; i <= num_party; i++) {
            if (i != party) {
                Plaintext table_pt_recv;
                elgl.get()->deserialize_recv(table_pt_recv, i);
                if (table_pt_recv.get_message().getUint64() != table_x) {
                    std::cerr << "Error x_sum: " << party << std::endl;
                    return 1;
                }
            }
        }
    }
    std::vector<Ciphertext> x_cipher(x_size);
    for (int i = 0; i < x_size; ++i) {
        x_cipher[i] = lvt->global_pk.encrypt(x_share[i]);
        lvt->Reconstruct_easy(x_share[i], elgl.get(), io.get(), &pool, party, num_party, fd);
    }

    std::vector<Ciphertext> x_ciphers(num_party);
    std::vector<Plaintext> out(x_size);
    std::vector<std::vector<Ciphertext>> out_ciphers(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [output1, output2] = lvt->lookup_online(x_share[i], x_cipher[i], x_ciphers);
        out[i] = output1;
        out_ciphers[i] = output2;
    } 
    vector<double> out_sum_double(x_size);
    for (int i = 0; i < x_size; ++i) {
        Plaintext out_sum = out[i];
        elgl.get()->serialize_sendall(out_sum);
        for (int j = 1; j <= num_party; j++) {
            if (j != party) {
                Plaintext out_recv;
                elgl.get()->deserialize_recv(out_recv, j);
                out_sum += out_recv;
                out_sum = out_sum % value_field;
            }
        }
        elgl.get()->serialize_sendall(out_sum);
        for (int j = 1; j <= num_party; j++) {
            if (j != party) {
                Plaintext out_sum_recv;
                elgl.get()->deserialize_recv(out_sum_recv, j);
                if (out_sum_recv.get_message().getUint64() != out_sum.get_message().getUint64()) {
                    std::cerr << "Error output" << std::endl;
                    return 1;
                }
            }
        }
        out_sum_double[i] = FixedPointConverter::decode(out_sum.get_message().getUint64());
        cout << "party: " << party << " out_sum_double = " << out_sum_double[i] << endl;
    }

    if (party == 1) {
        std::string output_file = "../Output/Output.txt";
        {
            std::ofstream out_file(output_file, std::ios::trunc);
            for (int i = 0; i < x_size; ++i) {
                out_file << out_sum_double[i] << std::endl;
            }
        }
    }

    return 0;
}
