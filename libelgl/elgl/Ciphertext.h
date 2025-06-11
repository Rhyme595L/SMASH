#pragma once

#include "libelgl/elgl/Plaintext.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/BLS12381Element.h"
#include <fstream>
class Ciphertext{
    BLS12381Element c0;
    BLS12381Element c1;

    public:
    Ciphertext(){};
    Ciphertext(const BLS12381Element& c0_, const BLS12381Element& c1_){
        c0 = c0_;
        c1 = c1_;
    };

    void set(const BLS12381Element& c0_, const BLS12381Element& c1_){
        c0 = c0_;
        c1 = c1_;
    }

    const BLS12381Element& get_c0() const{return c0;};
    const BLS12381Element& get_c1() const{return c1;};

    friend void add(Ciphertext &z, const Ciphertext &x, const Ciphertext &y);
    friend void sub(Ciphertext &z, const Ciphertext &x, const Ciphertext &y);

    Ciphertext operator+(const Ciphertext &other) const{
        Ciphertext result;
        add(result, *this, other);
        return result;
    };

    Ciphertext operator-(const Ciphertext &other) const{
        Ciphertext result;
        sub(result, *this, other);
        return result;
    };

    bool operator==(const Ciphertext &other) const{
        return c0 == other.c0 && c1 == other.c1;
    };

    bool operator!=(const Ciphertext &other) const{
        return c0 != other.c0 || c1 != other.c1;
    };

    Ciphertext& operator+=(const Ciphertext &other){
        add(*this, *this, other);
        return *this;
    }

    Ciphertext& operator-=(const Ciphertext &other){
        sub(*this, *this, other);
        return *this;
    }

    void pack(std::stringstream& os) const{
        c0.pack(os);
        c1.pack(os);
    };

    void unpack(std::stringstream& os){
        c0.unpack(os);
        c1.unpack(os);
    };

    size_t report_size() const{
        return G1::getSerializedByteSize() * 2;
    };

    static bool DeserializFromFile(std::string filepath, std::vector<Ciphertext>& p, size_t n){
        // load message from file
        std::ifstream file(filepath);
        if (file.is_open()){
            for (size_t i = 0; i < n; i++)
            {
                p[i].c0.getPoint().load(file);
                p[i].c1.getPoint().load(file);
            }
            file.close();
            return true;
        }else{
            std::cerr << "Error opening file: " << filepath << std::endl;
            return false;
        }

    }
    static bool SerializeToFile(std::string filepath, std::vector<Ciphertext>& p, size_t n){
        // pack message into file
        std::ofstream file(filepath);
        if (file.is_open()){
            for (size_t i = 0; i < n; i++)
            {
                p[i].c0.getPoint().save(file);
                p[i].c1.getPoint().save(file);
            }
            file.close();
            return true;
        }else{
            std::cerr << "Error opening file: " << filepath << std::endl;
            return false;
        }
    }
};