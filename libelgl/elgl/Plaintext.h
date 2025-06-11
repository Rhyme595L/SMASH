#ifndef _Plaintext
#define _Plaintext
#include <mcl/bls12_381.hpp>
// #include <gmpxx.h>

using namespace mcl::bn;
class Plaintext{
    Fr message;
    public:
    Plaintext();
    Plaintext(const Plaintext& other);
    Plaintext(const Fr& other);

    void assign_zero();
    void assign_one();
    void set_random();
    void set_random(mcl::Vint bound);
    void assign(const std::string num);
    void assign(const mpz_class num);
    const Fr& get_message() const{return message;};
    void set_message(const Fr& message_){message = message_;};

    void setHashof(const void *msg, size_t msgSize);

    static void pow(Plaintext &ret, const Plaintext &x, const Plaintext &exp);

    void add(Plaintext &z, const Plaintext &x, const Plaintext &y) const;
    void sub(Plaintext &z, const Plaintext &x, const Plaintext &y) const;
    void mul(Plaintext &z, const Plaintext &x, const Plaintext &y) const;
    void div(Plaintext &z, const Plaintext &x, const Plaintext &y) const;
    void sqr(Plaintext &z, const Plaintext &x) const;

    Plaintext operator+(const Plaintext &other) const{
        Plaintext result;
        add(result, *this, other);
        return result;
    }

    Plaintext operator-(const Plaintext &other) const{
        Plaintext result;
        sub(result, *this, other);
        return result;
    }

    Plaintext operator*(const Plaintext &other) const{
        Plaintext result;
        mul(result, *this, other);
        return result;
    }
    Plaintext operator/(const Plaintext &other) const{
        Plaintext result;
        div(result, *this, other);
        return result;
    }
    Plaintext operator+=(const Plaintext &other){
        add(*this, *this, other);
        return *this;
    }
    Plaintext operator-=(const Plaintext &other){
        sub(*this, *this, other);
        return *this;
    }
    Plaintext operator*=(const Plaintext &other){
        mul(*this, *this, other);
        return *this;
    }
    Plaintext operator/=(const Plaintext &other){
        div(*this, *this, other);
        return *this;
    }

    Plaintext operator=(const Plaintext &other){
        message = other.message;
        return *this;
    }

    void negate();

    bool equals(const Plaintext &other) const;

    bool operator==(const Plaintext &other) const{
        return equals(other);
    }

    bool operator!=(const Plaintext &other) const{
        return !equals(other);
    }

    void pack(std::stringstream& os) const;
    void unpack(std::stringstream& os);

    static bool DeserializFromFile(std::string filepath, Plaintext& p);
    static bool SerializeToFile(std::string filepath, Plaintext& p);

    uint64_t to_uint64() const;
    void xor_op(Plaintext &z, const Plaintext &x, const Plaintext &y) const;
    Plaintext operator^(const Plaintext &other) const;
    Plaintext operator^=(const Plaintext &other);

    void mod(Plaintext &z, const Plaintext &x, const Plaintext &modulus) const;
    Plaintext operator%(const Plaintext &modulus) const;
    Plaintext operator%=(const Plaintext &modulus);

    void mod2(Plaintext &z, const Plaintext &x) const;
    Plaintext operator%(int modulus) const;
    Plaintext operator%=(int modulus);
};

#endif