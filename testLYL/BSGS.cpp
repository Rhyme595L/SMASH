#include "emp-aby/BSGS.hpp"
#include "elgl/BLS12381Element.h"
#include <iostream>
#include <random>

const int thread_num = 4;
using namespace emp;
using namespace std;

int main() {
    BLS12381Element::init();
    BLS12381Element g = BLS12381Element::generator(); 

    cout << "g " << g.getPoint().b_.getUint64() << endl; 
    ThreadPool pool(thread_num);

    uint64_t N = 1ULL << 32; 
    BSGSPrecomputation bsgs;
     {
        std::cout << "预计算数据不存在或损坏，开始预计算..." << std::endl;
        auto start_time = chrono::high_resolution_clock::now();
        bsgs.precompute(g, N);
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        cout << "预计算用时: " << duration.count() << " 毫秒" << endl;
        std::cout << "预计算完成，保存到文件..." << std::endl;
        bsgs.serialize("bsgs_table.bin");
    }

    cout << "预计算完成，开始测试" << endl;

    std::random_device rd;
    std::mt19937_64 gen(rd());

    // 记录测试时间
    auto start_time = chrono::high_resolution_clock::now();
    // for (int test = 0; test < 10; ++test) {
        uint64_t m = gen() % N;
        mcl::bn::Fr m_fr; m_fr.setStr(std::to_string(m));
        BLS12381Element y = g * m_fr;

        int64_t m_rec = bsgs.solve_parallel_with_pool(y, &pool, thread_num);

        // cout << "Test " << test << ": ";
        if (m == (uint64_t)m_rec) {
            cout << "成功" << endl;
        } else {
            cout << "失败: m=" << m << " m_rec=" << to_string(m_rec) << endl;
        }
    // }
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    cout << "测试完成，用时: " << duration.count() << " 毫秒" << endl;
    return 0;
}
