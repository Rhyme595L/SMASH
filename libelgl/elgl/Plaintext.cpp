#include "libelgl/elgl/Plaintext.h"
#include <fstream>
// #include "gmpxx.h"

Plaintext::Plaintext(){
    message.clear();
}

Plaintext::Plaintext(const Plaintext& other){
    message = other.message;
}

Plaintext::Plaintext(const Fr& other){
    message = other;
}

void Plaintext::assign_zero(){
    message.clear();
}

void Plaintext::assign_one(){
    message = Fr(1);
}
void Plaintext::set_random(){
    message.setByCSPRNG();
}

void Plaintext::set_random(mcl::Vint bound){
    message.setByCSPRNG();
    if (message.getMpz() > bound){
        message.setMpz(message.getMpz() % bound);
    }
}


void Plaintext::setHashof(const void *msg, size_t msgSize){
    message.setHashOf(msg, msgSize);
}

void Plaintext::assign(const std::string num){
    message.setStr(num);
}

void Plaintext::assign(const mpz_class num){
    message.setMpz(num);
}

void Plaintext::add(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::add(z.message, x.message, y.message);
}
void Plaintext::sub(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::sub(z.message, x.message, y.message);
}
void Plaintext::mul(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::mul(z.message, x.message, y.message);
}
void Plaintext::div(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::div(z.message, x.message, y.message);
}
void Plaintext::sqr(Plaintext &z, const Plaintext &x) const{
    Fr::sqr(z.message, x.message);
}

void Plaintext::pow(Plaintext &ret, const Plaintext &x, const Plaintext &exp){
    mpz_class a_mpz, b_mpz, p_mpz, result;
    x.get_message().getMpz(a_mpz);
    exp.get_message().getMpz(b_mpz);
    std::string p;
    Fr::getModulo(p);
    p_mpz.setStr(p, 10);
    mcl::gmp::powMod(result, a_mpz, b_mpz, p_mpz);
    ret.assign(result);
}


void Plaintext::negate(){
    Fr::neg(message, message);
}

bool Plaintext::equals(const Plaintext &other) const{
    return message == other.message;
}

void Plaintext::pack(std::stringstream& os) const{
    this->message.save(os);
}
void Plaintext::unpack(std::stringstream& os){
    message.load(os);
}

uint64_t Plaintext::to_uint64() const {
    std::string str = message.getStr(10); 
    return static_cast<uint64_t>(std::stoull(str));
}

void Plaintext::xor_op(Plaintext &z, const Plaintext &x, const Plaintext &y) const {
    uint64_t x_val = x.to_uint64();
    uint64_t y_val = y.to_uint64();
    uint64_t result = x_val ^ y_val; 
    z.assign(std::to_string(result)); 
}

Plaintext Plaintext::operator^(const Plaintext &other) const {
    Plaintext result;
    xor_op(result, *this, other);
    return result;
}

Plaintext Plaintext::operator^=(const Plaintext &other) {
    xor_op(*this, *this, other);
    return *this;
}

void Plaintext::mod(Plaintext &z, const Plaintext &x, const Plaintext &modulus) const {
    mcl::Vint x_vint, mod_vint, result;
    x_vint.setStr(x.get_message().getStr(10)); 
    mod_vint.setStr(modulus.get_message().getStr(10));
    result = x_vint % mod_vint;
    z.assign(result.getStr(10)); 
}

void Plaintext::mod2(Plaintext &z, const Plaintext &x) const {
    uint64_t x_val = x.to_uint64();
    uint64_t result = x_val & 1;
    z.assign(std::to_string(result));
}

Plaintext Plaintext::operator%(const Plaintext &modulus) const {
    Plaintext result;
    mod(result, *this, modulus);
    return result;
}

Plaintext Plaintext::operator%=(const Plaintext &modulus) {
    mod(*this, *this, modulus);
    return *this;
}

Plaintext Plaintext::operator%(int modulus) const {
    if (modulus == 2) {
        Plaintext result;
        mod2(result, *this);
        return result;
    } else {
        throw std::invalid_argument("Only modulus 2 is supported for this operator.");
    }
}

Plaintext Plaintext::operator%=(int modulus) {
    if (modulus == 2) {
        mod2(*this, *this);
        return *this;
    } else {
        throw std::invalid_argument("Only modulus 2 is supported for this operator.");
    }
}

bool Plaintext::DeserializFromFile(std::string filepath, Plaintext& p){
    std::ifstream file(filepath);
    if (file.is_open()){
        p.message.load(file);
        file.close();
        return true;
    } else {
        std::cerr << "Unable to open file";
        return false;
    }
}

bool Plaintext::SerializeToFile(std::string filepath, Plaintext& p){
    std::ofstream file(filepath);
    if (file.is_open()){
        p.message.save(file);
        file.close();
        return true;
    }else{
        std::cerr << "Unable to open file";
        return false;
    }
}