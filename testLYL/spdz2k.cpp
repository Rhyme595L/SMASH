#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/spdz2k.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>

using namespace emp;
using namespace std;

int party, port;
const static int threads = 8;
int num_party;
const uint64_t FIELD_SIZE = (1ULL << 63);
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

    std::cout << "party: " << party << std::endl;
    int num = 16;
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
    std::cout << "party: " << party << std::endl;

    SPDZ2k<MultiIOBase> spdz2k(elgl);
    std::cout << "party: " << party << std::endl;

    if(party == 1) {
        for(int i = 2; i <= num_party; i++) {
            elgl->wait_for(i);
        }
    } else {
        elgl->send_done(1);
    }
    std::cout << "party: " << party << std::endl;

    std::cout << "\n==== Testing SPDZ2k Protocol ====\n" << std::endl;
    std::cout << "party: " << party << std::endl;
    std::cout << "party: " << party << std::endl;
    uint64_t test_input = party % FIELD_SIZE;
    SPDZ2k<MultiIOBase>::LabeledShare shared_value = spdz2k.distributed_share(test_input);
    uint64_t reconstructed = spdz2k.reconstruct(shared_value);
    std::cout << "Reconstructed value: " << reconstructed << std::endl;
    std::cout << "party: " << party << std::endl;
    uint64_t x1 = party % FIELD_SIZE;
    uint64_t x2 = party % FIELD_SIZE;
    SPDZ2k<MultiIOBase>::LabeledShare x1_share = spdz2k.distributed_share(x1);
    SPDZ2k<MultiIOBase>::LabeledShare x2_share = spdz2k.distributed_share(x2);
    std::cout << "\nTesting addition: " << x1 << " + " << x2 << std::endl;
    auto sum_share = spdz2k.add(x1_share, x2_share);
    uint64_t sum_result = spdz2k.reconstruct(sum_share);
    std::cout << "Addition result: " << sum_result << std::endl;
    std::cout << "party: " << party << std::endl;
    uint64_t scalar = 2 % FIELD_SIZE;
    auto scalar_mul_share = spdz2k.mul_const(x1_share, scalar);
    uint64_t scalar_mul_result = spdz2k.reconstruct(scalar_mul_share);
    std::cout << "\nTesting scalar multiplication: " << x1 << " * " << scalar << std::endl;
    std::cout << "Scalar multiplication result: " << scalar_mul_result << std::endl;
    std::cout << "\nTesting multiplication..." << std::endl;
    auto mul_share = spdz2k.multiply(x1_share, x2_share);
    uint64_t k1 = spdz2k.reconstruct(x1_share);
    uint64_t k2 = spdz2k.reconstruct(x2_share);
    uint64_t k3 = spdz2k.reconstruct(mul_share);
    std::cout << "\nTesting multiplication: " << k1 << " * " << k2 << std::endl;
    std::cout << "Multiplication result: " << k3 << std::endl;

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
