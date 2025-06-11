#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/spdz2k.hpp"
#include "L2A_spdz2k.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>

using namespace emp;
using namespace std;

int party, port;
const static int threads = 8;
int num_party;
const uint64_t FIELD_SIZE = 1ULL << 63;
const int num = 16; 
int m_bits = 32; 

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

    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    Fr alpha_fr = alpha.get_message();
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "init", alpha_fr, num, m_bits);

    lvt->DistKeyGen();

    SPDZ2k<MultiIOBase> spdz2k(elgl);
    if(party == 1) {
        for(int i = 2; i <= num_party; i++) {
            elgl->wait_for(i);
        }
    } else {
        elgl->send_done(1);
    }
    
    uint64_t x_spdz2k = spdz2k.rng() % FIELD_SIZE;
    Plaintext x;
    x.assign(to_string(x_spdz2k));
    Ciphertext cx;
    cx = lvt->global_pk.encrypt(x);

    vector<Ciphertext> vec_cx(num_party);
    vec_cx[party - 1] = cx;

    elgl->serialize_sendall(cx);
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cx_i;
            elgl->deserialize_recv(cx_i, i);
            vec_cx[i - 1] = cx_i;
        }
    }
    double total_time = 0;
    double total_comm = 0;
    double online_time = 0;
    double online_comm = 0;
    int times = 5;
    for (int i = 0; i < times; ++i) {
        auto shared_x = L2A_spdz2k::L2A(elgl, lvt, spdz2k, party, num_party, io, &pool, x, vec_cx, FIELD_SIZE, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    std::cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << std::endl;
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}