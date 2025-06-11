#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include "B2A_spdz2k.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>
#include <random>
#include <sstream>

using namespace emp;
using namespace std;

int party, port;
const static int threads = 8;
int num_party;
const int l = 32;
const uint64_t FIELD_SIZE = (1ULL << 63);
int m_bits = 1; // bits of message
int num = 1;

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
    std::string tablefile = "2";
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, num, m_bits);
    lvt->DistKeyGen();
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    TinyMAC<MultiIOBase> tiny(elgl);
    SPDZ2k<MultiIOBase> spdz2k(elgl);

    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    for (int i = 0; i < l; ++i) 
    {
        uint8_t bit_dis = tiny.rng() % 2;
        x_bits[i] = tiny.distributed_share(bit_dis);
    }
    
    double total_time = 0;
    double total_comm = 0;
    double online_time = 0;
    double online_comm = 0;
    int times = 1;
    for (int i = 0; i < times; ++i) {
        auto shared_x = B2A_spdz2k::B2A(elgl, lvt, tiny, spdz2k, party, num_party, io, &pool, FIELD_SIZE, x_bits, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    std::cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << std::endl;

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
