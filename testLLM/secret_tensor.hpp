#pragma once
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/spdz2k.hpp"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLYL/A2L_spdz2k.hpp"
#include "testLYL/L2A_spdz2k.hpp"
#include "FixedPointConverter.h"

#include <vector>
#include <cassert>
#include <initializer_list>
#include <iostream>
#include <thread>
#include <mcl/vint.hpp>
#include <random>
#include <sstream>

const int f = 16;
const int FixedPoint_bits = 24;
const int FixedPoint_SIZE = 1ULL << 24;
namespace emp {

enum class ShareType {
    SPDZ2k,
    LUT
};
template<typename IO = MultiIOBase>
class SecretTensor {
public:
    using Share = typename SPDZ2k<IO>::LabeledShare;

    SecretTensor(const std::vector<size_t>& shape, SPDZ2k<MultiIOBase>& spdz2k, ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, MPIOChannel<MultiIOBase>* io, ThreadPool* pool, int party, int num_party, const uint64_t& fd, ShareType type = ShareType::SPDZ2k) : shape(shape), spdz2k(spdz2k), elgl(elgl), lvt(lvt), io(io), pool(pool), party(party), num_party(num_party), fd(fd), type(type) {
        total_size = 1;
        for (auto dim : shape) total_size *= dim;

        if (type == ShareType::SPDZ2k) {
            data_spdz2k.resize(total_size);
        } else {
            data_lut_plain.resize(total_size);
            data_lut_cipher.resize(total_size);
        }
    }
    static SecretTensor from_plaintext(const std::vector<size_t>& shape, const std::vector<uint64_t>& values, SPDZ2k<MultiIOBase>& spdz2k, ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, MPIOChannel<MultiIOBase>* io, ThreadPool* pool, int party, int num_party, const uint64_t& fd, ShareType type = ShareType::SPDZ2k)
    {
        assert(values.size() == product(shape));

        SecretTensor tensor(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);

        if (type == ShareType::SPDZ2k) {
            for (size_t i = 0; i < values.size(); ++i) {
                tensor.data_spdz2k[i] = spdz2k.distributed_share_(values[i]);
            }
        } else {
            for (size_t i = 0; i < values.size(); ++i) {
                auto [plain, cipher] = A2L_spdz2k::A2L(elgl, lvt, spdz2k, party, num_party, static_cast<MultiIO*>(io), pool, spdz2k.distributed_share_(values[i]), fd, tensor.time_dummy, tensor.comm_dummy);
                tensor.data_lut_plain[i] = plain;
                tensor.data_lut_cipher[i] = cipher;
            }
        }

        return tensor;
    }

    SecretTensor add(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape == other.shape);

        SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        for (size_t i = 0; i < total_size; ++i) {
            result.data_spdz2k[i] = spdz2k.add(data_spdz2k[i], other.data_spdz2k[i]);
        }

        return result;
    }
    SecretTensor matmul(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape.size() == 2 && other.shape.size() == 2);
        assert(shape[1] == other.shape[0]);

        size_t m = shape[0], k = shape[1], n = other.shape[1];
        std::vector<size_t> result_shape = {m, n};
        SecretTensor result(result_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        for (size_t i = 0; i < m; ++i) {
            for (size_t j = 0; j < n; ++j) {
                Share acc = spdz2k.get_zero_share();
                for (size_t p = 0; p < k; ++p) {
                    size_t a_idx = i * k + p;
                    size_t b_idx = p * n + j;
                    Share prod = spdz2k.multiply_with_trunc(data_spdz2k[a_idx], other.data_spdz2k[b_idx], f);
                    acc = spdz2k.add(acc, prod);
                }
                result.data_spdz2k[i * n + j] = acc;
            }
        }

        return result;
    }
    void to_lut() {
        assert(type == ShareType::SPDZ2k);
        data_lut_plain.resize(total_size);
        data_lut_cipher.resize(total_size);

        for (size_t i = 0; i < total_size; ++i) {
            auto [plain, cipher] = A2L_spdz2k::A2L(elgl, lvt, spdz2k, party, num_party, static_cast<MultiIO*>(io), pool, data_spdz2k[i], fd, time_dummy, comm_dummy);
            data_lut_plain[i] = plain;
            data_lut_cipher[i] = cipher;
        }

        data_spdz2k.clear();
        type = ShareType::LUT;
    }
    void to_spdz2k() {
        assert(type == ShareType::LUT);
        data_spdz2k.resize(total_size);

        for (size_t i = 0; i < total_size; ++i) {
            data_spdz2k[i] = L2A_spdz2k::L2A(elgl, lvt, spdz2k, party, num_party, static_cast<MultiIO*>(io), pool, data_lut_plain[i], data_lut_cipher[i], fd, time_dummy, comm_dummy);
        }

        data_lut_plain.clear();
        data_lut_cipher.clear();
        type = ShareType::SPDZ2k;
    }
    size_t size() const { return total_size; }
    SecretTensor sub(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape == other.shape);
        SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        for (size_t i = 0; i < total_size; ++i) {
            result.data_spdz2k[i] = spdz2k.sub(data_spdz2k[i], other.data_spdz2k[i]);
        }
        return result;
    }
    SecretTensor mul(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape == other.shape);
        SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        for (size_t i = 0; i < total_size; ++i) {
            result.data_spdz2k[i] = spdz2k.multiply_with_trunc(data_spdz2k[i], other.data_spdz2k[i], f);
        }
        return result;
    }

private:
    static size_t product(const std::vector<size_t>& shape) {
        size_t p = 1;
        for (auto s : shape) p *= s;
        return p;
    }

public:
    std::vector<size_t> shape;
    ShareType type;
    std::vector<Share> data_spdz2k;
    std::vector<Plaintext> data_lut_plain;
    std::vector<std::vector<Ciphertext>> data_lut_cipher;
    SPDZ2k<IO>& spdz2k;
    ELGL<IO>* elgl;
    LVT<IO>* lvt;
    MPIOChannel<IO>* io;
    ThreadPool* pool;
    int party;
    int num_party;
    uint64_t fd;
    double time_dummy = 0.0;
    double comm_dummy = 0.0;

private:
    size_t total_size;
};

} // namespace emp