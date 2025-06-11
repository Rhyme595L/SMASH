#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>

using namespace emp;
using namespace std;

int party, port;
const static int threads = 8;
int num_party;

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

    TinyMAC<MultiIOBase> tinymac(elgl);

    if(party == 1) {
        for(int i = 2; i <= num_party; i++) {
            elgl->wait_for(i);
        }
    } else {
        elgl->send_done(1);
    }

    std::cout << "\n==== Testing TinyMAC Protocol ====" << std::endl;

    uint8_t test_input = party & 1;
    TinyMAC<MultiIOBase>::LabeledShare shared_value = tinymac.distributed_share(test_input);
    uint8_t reconstructed = tinymac.reconstruct(shared_value);
    std::cout << "Reconstructed value: " << int(reconstructed) << std::endl;

    uint8_t x1 = party & 1;
    uint8_t x2 = (party + 1) & 1;
    TinyMAC<MultiIOBase>::LabeledShare x1_share = tinymac.distributed_share(x1);
    TinyMAC<MultiIOBase>::LabeledShare x2_share = tinymac.distributed_share(x2);
    std::cout << "\nTesting XOR: " << int(x1) << " ^ " << int(x2) << std::endl;
    auto xor_share = tinymac.add(x1_share, x2_share);
    uint8_t xor_result = tinymac.reconstruct(xor_share);
    std::cout << "XOR result: " << int(xor_result) << std::endl;

    std::cout << "\nTesting AND: " << int(x1) << " & " << int(x2) << std::endl;
    auto and_share = tinymac.multiply(x1_share, x2_share);
    uint8_t and_result = tinymac.reconstruct(and_share);
    std::cout << "AND result: " << int(and_result) << std::endl;

    delete elgl;
    delete io;
    return 0;
}
