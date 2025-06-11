#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "B2L.hpp"
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
const int l = 24; 
int m_bits = 24; 
int num = 1;

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 4) {
        std::cout << "Usage: <party> <port> <num_party>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    
    std::vector<std::pair<std::string, unsigned short>> net_config;
    for (int i = 1; i <= num_party; ++i) {
        net_config.emplace_back("127.0.0.1", static_cast<unsigned short>(port + i - 1));
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    int skip_bytes_start = io->get_total_bytes_sent();
    auto skip_t1 = std::chrono::high_resolution_clock::now();

    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../bin/table_2.txt", alpha_fr, num, m_bits);
    lvt->DistKeyGen();
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);

    TinyMAC<MultiIOBase> tiny(elgl);
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        x_bits[i] = tiny.distributed_share(bit_dis(gen));
    }

    auto [shared_x, cips] = B2L::B2L(elgl, lvt, tiny, party, num_party, io, &pool, x_bits, 1ULL << l);

    int skip_bytes_end = io->get_total_bytes_sent();
    auto skip_t2 = std::chrono::high_resolution_clock::now();
    double skip_comm_kb = double(skip_bytes_end - skip_bytes_start) / 1024.0;
    double skip_time_ms = std::chrono::duration<double, std::milli>(skip_t2 - skip_t1).count();

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
