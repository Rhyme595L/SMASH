#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>
#include <experimental/filesystem>

using namespace emp;
namespace fs = std::experimental::filesystem;

int party, port;
const static int threads = 32;
int num_party;
int m_bits = 1; 
int num = 1;
int tb_size = 1ULL << num;

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
    Fr alpha_fr = alpha_init(num);
    std::string tablefile = "../bin/table_2.txt";
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, num, m_bits);
    lvt->DistKeyGen();
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);

    std::vector<Plaintext> x_share;
    std::string input_file = "../../TestLYL/Input/Input-P" + std::to_string(party) + ".txt";
    {
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            Plaintext x;
            x.assign(line);
            x_share.push_back(x);
            if (x.get_message().getUint64() > (1ULL << m_bits) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                cout << "Error value: " << x.get_message().getUint64() << ", tb_size = " << (1ULL << m_bits) << endl;
                return 1;
            }
        }
    }
    int x_size = x_share.size();
    
    std::vector<Ciphertext> x_cipher(x_size);
    for (int i = 0; i < x_size; ++i) {
        x_cipher[i] = lvt->global_pk.encrypt(x_share[i]);
    }

    std::vector<Ciphertext> x_ciphers(num_party);
    std::vector<Plaintext> out(x_size);
    std::vector<std::vector<Ciphertext>> out_ciphers(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [output1, output2] = lvt->lookup_online(x_share[i], x_cipher[i], x_ciphers);
        out[i] = output1;
        out_ciphers[i] = output2;
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
