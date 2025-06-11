#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>

using namespace emp;

int party, port;
const static int threads = 32;
int num_party;

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 4) {
        std::cout << "Format: <PartyID> <port> <num_parties>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);

    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc == 5) {
        const char* file = argv[4];
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
    int m_bits = 10; int m_size = 1 << m_bits; 
    int num = 10; int tb_size = 1ULL << num; 
    Fr alpha_fr = alpha_init(num);
    std::string tablefile = "init";
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, num, m_bits);
    lvt->DistKeyGen();
    cout << "Finish DistKeyGen" << endl;
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    mpz_class fd = m_size;
    cout << "Finish generate_shares" << endl;

    std::vector<Plaintext> x_share;
    std::string input_file = "../Input/Input-P" + std::to_string(party) + ".txt";
    {
        // 判断文件是否存在
        if (!fs::exists(input_file)) {
            std::cerr << "Error: input file does not exist: " << input_file << std::endl;
            return 1;
        }
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            Plaintext x;
            x.assign(line);
            x_share.push_back(x);
            if (x.get_message().getUint64() > (1ULL << num) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                cout << "Error value: " << x.get_message().getUint64() << ", tb_size = " << (1ULL << m_bits) << endl;
                return 1;
            }
        }
    }
    int x_size = x_share.size();
    cout << "Finish input generation" << endl;
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
    Plaintext tb_field = Plaintext(tb_size);
    Plaintext value_field = Plaintext(m_size);
    cout << "Finish input size check" << endl;

    for (int i = 0; i < x_size; ++i) {
        Plaintext x_sum = x_share[i];
        elgl->serialize_sendall(x_sum);
        for (int i = 1; i <= num_party; i++) {
            if (i != party) {
                Plaintext x_recv;
                elgl->deserialize_recv(x_recv, i);
                x_sum += x_recv;
                x_sum = x_sum % tb_field;
            }
        }
        uint64_t table_x = lvt->table[x_sum.get_message().getUint64()];
        std::cout << "x: " << x_sum.get_message().getUint64() << ", lut[x]: " << table_x << endl;
        Plaintext table_pt = Plaintext(table_x);
        elgl->serialize_sendall(table_pt);
        for (int i = 1; i <= num_party; i++) {
            if (i != party) {
                Plaintext table_pt_recv;
                elgl->deserialize_recv(table_pt_recv, i);
                if (table_pt_recv.get_message().getUint64() != table_x) {
                    std::cerr << "Error x_sum: " << party << std::endl;
                    return 1;
                }
                cout << "party: " << party << " table_pt = " << table_pt_recv.get_message().getStr() << endl;
            }
        }
    }
    std::vector<Ciphertext> x_cipher(x_size);
    for (int i = 0; i < x_size; ++i) {
        x_cipher[i] = lvt->global_pk.encrypt(x_share[i]);
        lvt->Reconstruct_interact(x_share[i], x_cipher[i], elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, fd);
    }

    std::vector<Ciphertext> x_ciphers(num_party);
    std::vector<Plaintext> out(x_size);
    std::vector<std::vector<Ciphertext>> out_ciphers(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [output1, output2] = lvt->lookup_online(x_share[i], x_cipher[i], x_ciphers);
        out[i] = output1;
        out_ciphers[i] = output2;
    } 

    cout << "Finish online lookup" << endl;
    lvt->Reconstruct_interact(out[0], out_ciphers[0][party-1], elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, fd);
    cout << "Finish Reconstruct_interact" << endl;
    lvt->Reconstruct(out[0], out_ciphers[0], elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, fd);
    for (int i = 0; i < x_size; ++i) {
        Plaintext out_sum = out[i];
        elgl->serialize_sendall(out_sum);
        for (int i = 1; i <= num_party; i++) {
            if (i != party) {
                Plaintext out_recv;
                elgl->deserialize_recv(out_recv, i);
                out_sum += out_recv;
                out_sum = out_sum % value_field;
            }
        }
        elgl->serialize_sendall(out_sum);
        for (int i = 1; i <= num_party; i++) {
            if (i != party) {
                Plaintext out_sum_recv;
                elgl->deserialize_recv(out_sum_recv, i);
                if (out_sum_recv.get_message().getUint64() != out_sum.get_message().getUint64()) {
                    std::cerr << "Error output" << std::endl;
                    return 1;
                }
                cout << "party: " << party << " out_sum = " << out_sum.get_message().getStr() << endl;
            }
        }
    }

    std::string output_file = "../../TestLYL/Output/Output-P" + std::to_string(party) + ".txt";
    {
        std::ofstream out_file(output_file, std::ios::trunc);
        for (int i = 0; i < x_size; ++i) {
            out_file << out[i].get_message().getStr() << std::endl;
        }
    }

    delete lvt;
    delete elgl;
    delete io;
    return 0;
}
