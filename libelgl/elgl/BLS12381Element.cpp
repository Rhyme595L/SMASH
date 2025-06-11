#include "libelgl/elgl/BLS12381Element.h"
#include <mcl/bn.hpp>

using namespace mcl::bn;
void BLS12381Element::init()
{
    initPairing(mcl::BLS12_381);
}

BLS12381Element::BLS12381Element(){
    point = G1();
    point.clear();
}

BLS12381Element::BLS12381Element(const Fr& other) :
        BLS12381Element()
{
    std::string g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    point.setStr(g1Str);
    G1::mul(point, point, other);
}

BLS12381Element::BLS12381Element(const BLS12381Element& other){
    point = other.point;
}

BLS12381Element::~BLS12381Element(){
    point.clear();
}

BLS12381Element& BLS12381Element::operator =(const BLS12381Element& other)
{
    point = other.point;
    return *this;
}

BLS12381Element BLS12381Element::operator+(const BLS12381Element& other) const
{
    BLS12381Element res;
    G1::add(res.point, point, other.point);
    res.point.normalize();
    return res;
}

BLS12381Element BLS12381Element::operator-(const BLS12381Element& other) const
{
    BLS12381Element res;
    G1::sub(res.point, point, other.point);
    res.point.normalize();
    return res;
}

void BLS12381Element::check(){
    assert(point.isValid());
}

BLS12381Element BLS12381Element::operator*(const Fr& other) const{
    BLS12381Element res;
    G1::mul(res.point, point, other);
    res.point.normalize();
    return res;
}

BLS12381Element& BLS12381Element::operator*=(const Fr& other){
    G1::mul(point, point, other);
    return *this;
}

BLS12381Element& BLS12381Element::operator/=(const Fr& other){
    Fr inv_Fr;
    Fr::inv(inv_Fr, other);
    G1::mul(point, point, inv_Fr);
    return *this;
}

BLS12381Element& BLS12381Element::operator+=(const BLS12381Element& other){
    G1::add(point, point, other.point);
    return *this;
}
BLS12381Element& BLS12381Element::operator-=(const BLS12381Element& other){
    G1::sub(point, point, other.point);
    return *this;
}

bool BLS12381Element::operator==(const BLS12381Element& other) const{
    return point == other.point;
}

bool BLS12381Element::operator!=(const BLS12381Element& other) const{
    return point != other.point;
}

void BLS12381Element::pack(std::stringstream& os, int) const{
    point.save(os);
}

void BLS12381Element::pack(cybozu::MemoryOutputStream& os) const{
    point.save(os);
}

void BLS12381Element::unpack(std::stringstream& os, int){
    point.load(os);
}

void BLS12381Element::unpack(cybozu::MemoryInputStream& is) {
    point.load(is);
}

std::ostream& operator<<(std::ostream& s, const BLS12381Element& x){
    std::ostringstream ss;
    x.point.save(ss);
    s << ss.str();
    return s;
}

void BLS12381Element::output(std::ostream& s, bool human) const{
    assert(human);
    s << *this;
}

void BLS12381Element::print_str() const{
    std::ostringstream ss;
    point.save(ss, mcl::IoSerializeHexStr);
    std::cout << ss.str() << std::endl;
}

BLS12381Element operator*(const Fr& a, const BLS12381Element& b){
    return b * a;
}

BLS12381Element BLS12381Element::generator() {
    BLS12381Element g;
    std::string g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    g.point.setStr(g1Str);
    return g;
}

BLS12381Element BLS12381Element::negate() const {
    BLS12381Element res;
    res.point = this->point;
    mcl::bn::G1::neg(res.point, res.point);
    return res;
}