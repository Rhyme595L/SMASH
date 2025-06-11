#include "libelgl/elgl/ELGL_Key.h"
#include <fstream>
ELGL_PK::ELGL_PK(ELGL_SK& sk){
    pk = BLS12381Element(sk.get_sk());
}

void ELGL_PK::encrypt(Ciphertext &c, const Plaintext& m) const{
    Fr r;
    r.setByCSPRNG();
    BLS12381Element rG1 = BLS12381Element(r);
    c = Ciphertext(rG1, pk * r + BLS12381Element(m.get_message()));
}

Ciphertext ELGL_PK::encrypt(const Plaintext& m) const{
    Fr r;
    r.setByCSPRNG();
    BLS12381Element rG1 = BLS12381Element(r);
    return Ciphertext(rG1, pk * r + BLS12381Element(m.get_message()));
}

void ELGL_PK::encrypt(Ciphertext& c, const Plaintext& mess, const Random_C rc) const{
    BLS12381Element rG1 = BLS12381Element(rc);
    c = Ciphertext(rG1, pk * rc + BLS12381Element(mess.get_message()));
}

Ciphertext ELGL_PK::encrypt(const Plaintext& mess, const Random_C rc) const{
    BLS12381Element rG1 = BLS12381Element(rc);
    return Ciphertext(rG1, pk * rc + BLS12381Element(mess.get_message()));
}

void ELGL_PK::KeyGen(ELGL_SK & sk){
    pk = BLS12381Element(sk.get_sk());
}
void ELGL_SK::decrypt(BLS12381Element &m, const Ciphertext& c) const{
    BLS12381Element tmp = c.get_c0() * sk;
    m = c.get_c1() - tmp;
    
}

BLS12381Element ELGL_SK::decrypt(const Ciphertext& c) const{
    BLS12381Element tmp = c.get_c0() * sk;
    tmp = c.get_c1() - tmp;
    return tmp;
}

void KeyGen(ELGL_PK& PK, ELGL_SK& SK){
    Fr sk_;
    sk_.setByCSPRNG();
    SK.assign_sk(sk_);
    PK.KeyGen(SK);
}

bool ELGL_SK::DeserializFromFile(std::string filepath, ELGL_SK& p){
    std::ifstream file(filepath);
    if (file.is_open()){
        p.sk.load(file);
        return true;
    }else{
        std::cerr << "Unable to open file";
        return false;
    }
}
bool ELGL_SK::SerializeToFile(std::string filepath, ELGL_SK& p){
    std::ofstream file(filepath);
    if (file.is_open()){
        p.sk.save(file);
        file.close();
        return true;
    }else{
        std::cerr << "Unable to open file";
        return false;
    }
}

bool ELGL_PK::DeserializFromFile(std::string filepath, ELGL_PK& p){
    std::ifstream file(filepath);
    if (file.is_open()){
        p.pk.getPoint().load(file);
        file.close();
        return true;
    }else{
        std::cerr << "Unable to open file";
        return false;
    }
}
bool ELGL_PK::SerializeToFile(std::string filepath, ELGL_PK& p){
    std::ofstream file(filepath);
    if (file.is_open()){
        p.pk.getPoint().save(file);
        file.close();
        return true;
    }else{
        std::cerr << "Unable to open file";
        return false;
    }
}