#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "L2B.hpp"
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
const int num = 1;
const int num_bits = 24;
const uint64_t FIELD_SIZE = (1ULL << num_bits);
const mcl::Vint MODULUS(FIELD_SIZE);

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

    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../bin/table_2.txt", alpha_fr, num, num_bits);

    TinyMAC<MultiIOBase> tiny(elgl);
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    Plaintext x_arith;
    x_arith.assign(65549);

    vector<Ciphertext> x_cips(num_party);
    x_cips[party - 1] = lvt->global_pk.encrypt(x_arith);
    elgl->serialize_sendall(x_cips[party - 1]);
    for (int i = 0; i < num_party; ++i) {
        if (i != party - 1) {
            elgl->deserialize_recv(x_cips[i], i + 1);
        }
    }
    cout << "x_arith: " << lvt->Reconstruct(x_arith, x_cips, elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, MODULUS).get_message().getUint64() << endl;
    auto x_bool = L2B::L2B(elgl, lvt, tiny, party, num_party, io, &pool, FIELD_SIZE, num_bits, x_arith, x_cips);
    vector<int> bits;
    for (int j = 0; j < num_bits; ++j) {
        int bit = tiny.reconstruct(x_bool[j]);
        bits.push_back(bit);
    }
    uint64_t decimal_value = bits_to_decimal(bits, FIELD_SIZE);
    cout << "x_bits" << decimal_value << endl;
    
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}