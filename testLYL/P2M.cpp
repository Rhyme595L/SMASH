#include "emp-aby/P2M.hpp"
#include "emp-aby/io/multi-io.hpp"
#include <iostream>
#include <random>

const int thread_num = 4;
using namespace emp;
using namespace std;

std::map<std::string, Fr> test_P_to_m(size_t max_exponent) {
    std::map<std::string, Fr> P_to_m;
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i <= max_exponent; ++i) {
        BLS12381Element g_i(i);
        P_to_m[g_i.getPoint().getStr()] = Fr(i);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    std::cout << "构建表大小 " << max_exponent << " 用时: " << elapsed.count() << " 秒" << std::endl;
    std::cout << "表大小: " << P_to_m.size() << " 项" << std::endl;
    
    return P_to_m;
}

int main() {
    BLS12381Element::init();
    int num_party = 2;  
    int table_size = 17;  
    size_t max_exponent = (1ULL << table_size);  
    std::map<std::string, Fr> P_to_m;
    if (file_exists("P_to_m_table.bin")) {
        std::cout << "开始读取表..." << std::endl;
        deserialize_P_to_m(P_to_m, "P_to_m_table.bin");
    } else {
        std::cout << "开始构建表，max_exponent = " << max_exponent << std::endl;
        auto P_to_m = test_P_to_m(max_exponent);
        
        std::cout << "保存表到文件..." << std::endl;
        serialize_P_to_m(P_to_m, "P_to_m_table.bin");
    }
    
    auto start_time = chrono::high_resolution_clock::now();

    std::cout << "从文件读取表..." << std::endl;
    std::map<std::string, Fr> loaded_P_to_m;
    deserialize_P_to_m(loaded_P_to_m, "P_to_m_table.bin");
    
    BLS12381Element g(100000);
    auto it = loaded_P_to_m.find(g.getPoint().getStr());
    if (it == loaded_P_to_m.end()) {
        std::cerr << "[Error] pi_ask not found in P_to_m! pi_ask = " << g.getPoint().getStr() << std::endl;
        exit(1);
    } else {
        std::cout << "查找成功，值 = " << it->second << std::endl;
    }
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    cout << "测试完成，用时: " << duration.count() << " 毫秒" << endl;

    return 0;
}