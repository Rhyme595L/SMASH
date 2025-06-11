#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/mascot.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>

using namespace emp;
using namespace std;

// Test constants
int party, port;
const static int threads = 8;
int num_party;
const mcl::Vint FIELD_SIZE("52435875175126190479447740508185965837690552500527637822603658699938581184512");
// const int FIELD_SIZE = 1000000007; // A prime number for modular arithmetic
int m_bits = 32; // bits of message

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

    int num = 28; 
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    // std::cout << "alpha: " << alpha.get_message().getStr() << std::endl;
    Fr alpha_fr = alpha.get_message();
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "init", alpha_fr, num, m_bits);

    lvt->DistKeyGen();

    MASCOT<MultiIOBase> mascot(elgl);
    
    if(party == 1) {
        for(int i = 2; i <= num_party; i++) {
            elgl->wait_for(i);
        }
    } else {
        elgl->send_done(1);
    }
    
    std::cout << "\n==== Testing MASCOT Protocol ====\n" << std::endl;
    mcl::Vint test_input; 
    test_input = party; 
    test_input %= FIELD_SIZE;
    MASCOT<MultiIOBase>::LabeledShare shared_value;
    shared_value = mascot.distributed_share(test_input);

    mcl::Vint reconstructed = mascot.reconstruct(shared_value);
    
    std::cout << "Reconstructed value: " << reconstructed.getStr() << std::endl;
    
    mcl::Vint x1, x2; 
    x1 = party; x1 %= FIELD_SIZE; 
    x2 = party; x2 %= FIELD_SIZE;
    MASCOT<MultiIOBase>::LabeledShare x1_share, x2_share;
    
    std::cout << "\nTesting addition: " << x1.getStr() << " + " << x2.getStr() << std::endl;
    x1_share = mascot.distributed_share(x1);
    x2_share = mascot.distributed_share(x2);
    
    auto sum_share = mascot.add(x1_share, x2_share);
    mcl::Vint sum_result = mascot.reconstruct(sum_share);
    
    std::cout << "Addition result: " << sum_result.getStr() << std::endl;
    
    mcl::Vint scalar; scalar = 2; scalar %= FIELD_SIZE;
    
    auto scalar_mul_share = mascot.mul_const(x1_share, scalar);
    mcl::Vint scalar_mul_result = mascot.reconstruct(scalar_mul_share);
    
    std::cout << "\nTesting scalar multiplication: " << x1.getStr() << " * " << scalar.getStr() << std::endl;
    std::cout << "Scalar multiplication result: " << scalar_mul_result.getStr() << std::endl;
    
    std::cout << "\nTesting multiplication..." << std::endl;
    auto mul_share = mascot.multiply(x1_share, x2_share);

    mcl::Vint k1 = mascot.reconstruct(x1_share);
    mcl::Vint k2 = mascot.reconstruct(x2_share);
    mcl::Vint k3 = mascot.reconstruct(mul_share);
    
    std::cout << "\nTesting multiplication: " << k1.getStr() << " * " << k2.getStr() << std::endl;
    std::cout << "Multiplication result: " << k3.getStr() << std::endl;
    
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}