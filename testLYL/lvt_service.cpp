#include "lvt_llm.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <memory>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <map>
#include <mutex>

constexpr int BACKLOG = 2;
constexpr int MAX_OPTYPE_LEN = 32;

struct LVTContext {
    std::unique_ptr<emp::LVT<emp::MultiIOBase>> lvt;
    std::unique_ptr<emp::MultiIO> io;
    std::unique_ptr<emp::ELGL<emp::MultiIOBase>> elgl;
    std::unique_ptr<ThreadPool> pool;
    bool initialized = false;
};
std::map<std::string, std::unique_ptr<LVTContext>> g_lvt_map;
std::mutex g_lvt_map_mutex;
void initialize_lvt(int party, int num_party, int lvt_port, const std::string& func_name) {
    if (g_lvt_map[func_name]->initialized) return;
    auto tup = lvt_llm::lvt_offline_phase(party, num_party, lvt_port, func_name);
    g_lvt_map[func_name]->lvt = std::move(std::get<0>(tup));
    g_lvt_map[func_name]->io = std::move(std::get<1>(tup));
    g_lvt_map[func_name]->elgl = std::move(std::get<2>(tup));
    g_lvt_map[func_name]->pool = std::move(std::get<3>(tup));
    g_lvt_map[func_name]->initialized = true;
    std::cout << "[LVT Service] Offline phase done." << std::endl;
}

LVTContext* get_or_init_lvt(const std::string& op_type, int party, int num_party, int lvt_port) {
    std::lock_guard<std::mutex> lock(g_lvt_map_mutex);
    auto it = g_lvt_map.find(op_type);
    if (it != g_lvt_map.end() && it->second->initialized) {
        return it->second.get();
    }
    auto ctx = std::make_unique<LVTContext>();
    auto tup = lvt_llm::lvt_offline_phase(party, num_party, lvt_port, op_type);
    ctx->lvt = std::move(std::get<0>(tup));
    ctx->io = std::move(std::get<1>(tup));
    ctx->elgl = std::move(std::get<2>(tup));
    ctx->pool = std::move(std::get<3>(tup));
    ctx->initialized = true;
    auto* ptr = ctx.get();
    g_lvt_map[op_type] = std::move(ctx);
    std::cout << "[LVT Service] Offline phase done for op: " << op_type << std::endl;
    return ptr;
}
std::vector<float> process_vector(const std::vector<float>& input, const std::string& op_type, int party, int num_party, int lvt_port) {
    LVTContext* ctx = get_or_init_lvt(op_type, party, num_party, lvt_port);
    if (!ctx) {
        std::cerr << "[LVT Service] LVTContext init failed for op: " << op_type << std::endl;
        return {};
    }
    return std::get<0>(lvt_llm::lvt_online_phase(input, ctx->lvt.get(), ctx->io.get(), ctx->elgl.get(), ctx->pool.get(), party, num_party));
}

int main(int argc, char** argv) {
    if (argc < 6) {
        std::cerr << "用法: " << argv[0] << " <python_port> <party> <lvt_port> <num_party> <func_name>" << std::endl;
        return 1;
    }
    int python_port = atoi(argv[1]);
    int party = atoi(argv[2]);
    int lvt_port = atoi(argv[3]);
    int num_party = atoi(argv[4]);
    std::string func_name = argv[5];

    std::cout << "[LVT Service] 启动参数: python_port=" << python_port << ", party=" << party << ", lvt_port=" << lvt_port << ", num_party=" << num_party << ", func=" << func_name << std::endl;
    get_or_init_lvt(func_name, party, num_party, lvt_port);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(python_port);
    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, BACKLOG) < 0) { perror("listen"); return 1; }
    std::cout << "[LVT Service] Listening on 0.0.0.0:" << python_port << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) { perror("accept"); continue; }
        char op_type_buf[33] = {0};
        if (read(client_fd, op_type_buf, 32) != 32) { close(client_fd); continue; }
        std::string op_type(op_type_buf, strnlen(op_type_buf, 32));
        if (op_type == "exit") { close(client_fd); break; }
        int32_t data_len = 0;
        if (read(client_fd, &data_len, sizeof(data_len)) != sizeof(data_len)) { close(client_fd); continue; }
        if (data_len <= 0 || data_len > 2*1000*1000) { close(client_fd); continue; }
        std::vector<float> input(data_len);
        size_t to_read = data_len * sizeof(float);
        char* ptr = reinterpret_cast<char*>(input.data());
        size_t total = 0;
        while (total < to_read) {
            ssize_t n = read(client_fd, ptr+total, to_read-total);
            if (n <= 0) break;
            total += n;
        }
        if (total != to_read) { close(client_fd); continue; }
        std::vector<float> result = process_vector(input, op_type, party, num_party, lvt_port);
        int32_t result_len = result.size();
        write(client_fd, &result_len, sizeof(result_len));
        write(client_fd, result.data(), result_len * sizeof(float));
        close(client_fd);
    }
    close(server_fd);
    std::cout << "[LVT Service] Exit." << std::endl;
    return 0;
}
 