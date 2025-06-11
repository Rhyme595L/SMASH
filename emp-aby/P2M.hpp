#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <cstddef>
#include <cstring>
#include "libelgl/elgl/BLS12381Element.h"

void serialize_P_to_m(const std::map<std::string, Fr>& P_to_m, const char* filename) {
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr << "Error: Unable to open file for writing P_to_m table.\n";
        return;
    }

    // 写入表大小
    size_t size = P_to_m.size();
    outFile.write(reinterpret_cast<const char*>(&size), sizeof(size));

    // 写入每个键值对
    for (const auto& pair : P_to_m) {
        // 写入key的长度和内容
        size_t key_len = pair.first.length();
        outFile.write(reinterpret_cast<const char*>(&key_len), sizeof(key_len));
        outFile.write(pair.first.c_str(), key_len);

        // 写入value
        std::string value_str = pair.second.getStr();
        size_t value_len = value_str.length();
        outFile.write(reinterpret_cast<const char*>(&value_len), sizeof(value_len));
        outFile.write(value_str.c_str(), value_len);
    }

    outFile.close();
}

void deserialize_P_to_m(std::map<std::string, Fr>& P_to_m, const char* filename) {
    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        std::cerr << "Error: Unable to open file for reading P_to_m table.\n";
        return;
    }

    // 读取表大小
    size_t size;
    inFile.read(reinterpret_cast<char*>(&size), sizeof(size));

    // 读取每个键值对
    for (size_t i = 0; i < size; ++i) {
        // 读取key
        size_t key_len;
        inFile.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
        std::string key(key_len, '\0');
        inFile.read(&key[0], key_len);

        // 读取value
        size_t value_len;
        inFile.read(reinterpret_cast<char*>(&value_len), sizeof(value_len));
        std::string value_str(value_len, '\0');
        inFile.read(&value_str[0], value_len);

        // 构造Fr并插入map
        Fr value;
        value.setStr(value_str);
        P_to_m[key] = value;
    }

    inFile.close();
}