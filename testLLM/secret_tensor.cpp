#include "secret_tensor.hpp"
#include "FixedPointConverter.h"
#include "emp-aby/emp-aby.h"
#include <iostream>

using namespace emp;
int party, port;
const static int threads = 8;
int num_party;
int fixedpoint_bits = 24;

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

    Fr alpha_fr = alpha_init(fixedpoint_bits);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "init", alpha_fr, fixedpoint_bits, fixedpoint_bits);
    lvt->DistKeyGen();
    SPDZ2k<MultiIOBase> spdz2k(elgl);

    std::vector<size_t> shape = {2, 2};
    std::vector<uint64_t> plain_values = {1, 2, 3, 4};

    using ST = SecretTensor<MultiIOBase>;
    auto tensor = ST::from_plaintext(shape, plain_values, spdz2k, elgl, lvt, static_cast<MPIOChannel<MultiIOBase>*>(io), &pool, party, num_party, fixedpoint_bits);

    tensor.to_lut();
    tensor.to_spdz2k();
    
    std::vector<uint64_t> revealed;
    for (const auto& share : tensor.data_spdz2k) {
        revealed.push_back(spdz2k.reconstruct(share));
    }

    std::vector<uint64_t> A_current_share = {
        FixedPointConverter::encode(1.0),
        FixedPointConverter::encode(2.0),
        FixedPointConverter::encode(-3.0),
        FixedPointConverter::encode(-4.5)
    }; 
    std::vector<uint64_t> B_current_share = {
        FixedPointConverter::encode(1.0),
        FixedPointConverter::encode(2.0),
        FixedPointConverter::encode(-3.0),
        FixedPointConverter::encode(-4.5)
    };

    auto A_current = SecretTensor<MultiIOBase>::from_plaintext({2, 2}, A_current_share, spdz2k, elgl, lvt, io, &pool, party, num_party, fixedpoint_bits);
    auto B_current = SecretTensor<MultiIOBase>::from_plaintext({2, 2}, B_current_share, spdz2k, elgl, lvt, io, &pool, party, num_party, fixedpoint_bits);

    auto C_add = A_current.add(B_current); 
    auto C_mul = A_current.matmul(B_current); 
    std::cout << "Revealed A + B: "; 
    for (const auto& s : C_add.data_spdz2k){
        uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
        std::cout << FixedPointConverter::decode(v) << " ";
    }
    std::cout << "\n";

    std::cout << "Revealed A x B: ";
    for (const auto& s : C_mul.data_spdz2k){
        uint64_t raw_value = spdz2k.reconstruct(s);
        std::cout << FixedPointConverter::decode(raw_value % FixedPoint_SIZE) << " ";
    }
    std::cout << "\n";

    auto C_sub = A_current.sub(B_current);
    std::cout << "Revealed A - B: "; 
    for (const auto& s : C_sub.data_spdz2k){
        uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
        std::cout << FixedPointConverter::decode(v) << " ";
    }
    std::cout << "\n";

    auto C_elemul = A_current.mul(B_current);
    std::cout << "Revealed A .* B: ";
    for (const auto& s : C_elemul.data_spdz2k){
        uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
        std::cout << FixedPointConverter::decode(v) << " ";
    }
    std::cout << "\n";

    delete io;
    return 0;
}
