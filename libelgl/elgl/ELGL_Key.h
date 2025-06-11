#ifndef _ELGL_Key
#define _ELGL_Key

#include "libelgl/elgl/Ciphertext.h"
#include "libelgl/elgl/BLS12381Element.h"
#include "libelgl/elgl/Plaintext.h"
#include <map>
class ELGL_PK;
class Ciphertext;
class ELGL_SK{
    public:
    Fr sk;

    // don't know why it returns 0
    static int size(){return 0;};

    Fr get_sk() const{return sk;};

    void assign_sk(const Fr& sk_){sk = sk_;};

    void assign_sk(const std::string sk_){
        sk.setStr(sk_);
    };

    ELGL_SK(){};

    void pack(std::stringstream& os) const{
        sk.save(os);
    };

    void unpack(std::stringstream& os){
        sk.load(os);
    };

    static bool DeserializFromFile(std::string filepath, ELGL_SK& p);
    static bool SerializeToFile(std::string filepath, ELGL_SK& p);

    void decrypt(BLS12381Element &m, const Ciphertext& c) const;

    BLS12381Element decrypt(const Ciphertext& c) const;

    friend void KeyGen(ELGL_PK& PK, ELGL_SK& SK);

    ELGL_SK& operator+=(const ELGL_SK& c){
        Fr::add(sk, sk, c.sk);
        return *this;
    }

    ELGL_SK operator+(const ELGL_SK& x) const {
        ELGL_SK result;
        Fr::add(result.sk, sk, x.sk);
        return result;
    }

    bool operator!=(const ELGL_SK& other) const{
        return sk != other.sk;
    }
};

class ELGL_PK{
    BLS12381Element pk;
    public:
    typedef Fr Random_C;
    BLS12381Element get_pk() const{return pk;};
    void assign_pk(const BLS12381Element& pk_){pk = pk_;};

    ELGL_PK(){pk = BLS12381Element();};

    ELGL_PK(ELGL_SK& sk);

    void encrypt(Ciphertext &c, const Plaintext& m) const;

    Ciphertext encrypt(const Plaintext& mess) const;

    void encrypt(Ciphertext& c, const Plaintext& mess, const Random_C rc) const;

    Ciphertext encrypt(const Plaintext& mess, const Random_C rc) const;

    friend void KeyGen(ELGL_PK& PK, ELGL_SK& SK);
    void KeyGen(ELGL_SK & sk);

    void pack(std::stringstream& os) const {pk.pack(os);};

    void unpack(std::stringstream& os) {pk.unpack(os);};

    static bool DeserializFromFile(std::string filepath, ELGL_PK& p);
    static bool SerializeToFile(std::string filepath, ELGL_PK& p);

    bool operator!= (const ELGL_PK& other) const{
        return pk!= other.pk;
    };
};

class ELGL_KeyPair{
    public:
    ELGL_PK pk;
    ELGL_SK sk;
    ELGL_KeyPair(){};
    void generate(){
        KeyGen(pk, sk);
    };
    ELGL_PK get_pk() const{return pk;};
    ELGL_SK get_sk() const{return sk;};
};

#endif