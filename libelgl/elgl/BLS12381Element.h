#ifndef BLS12381_BLS12381ELEMENT_H_
#define BLS12381_BLS12381ELEMENT_H_
#include <mcl/bls12_381.hpp>

using namespace mcl::bn;

class BLS12381Element{
    public:
        // typedef gfp_<2, 4> Scalar;
    
    G1 point;

    public:
    static int size() { return 0; }
    static int length() { return 384; }
    static std::string type_string() { return "BLS12381"; }
    void print_str() const;

    G1 getPoint() const { return point; }

    static void init();

    BLS12381Element();
    BLS12381Element(const BLS12381Element& other);
    BLS12381Element(const Fr& other);
    ~BLS12381Element();

    BLS12381Element& operator=(const BLS12381Element& other);

    void check();
    // Scalar x() const;

    BLS12381Element operator+(const BLS12381Element& other) const;
    BLS12381Element operator-(const BLS12381Element& other) const;
    BLS12381Element operator*(const Fr& other) const;

    BLS12381Element& operator+=(const BLS12381Element& other);
    BLS12381Element& operator-=(const BLS12381Element& other);
    BLS12381Element& operator*=(const Fr& other);
    BLS12381Element& operator/=(const Fr& other);

    bool operator==(const BLS12381Element& other) const;
    bool operator!=(const BLS12381Element& other) const;

    void pack(std::stringstream& os, int = -1) const;
    void pack(cybozu::MemoryOutputStream& os) const;
    void unpack(std::stringstream& os, int = -1);
    void unpack(cybozu::MemoryInputStream& is) ;
    
    void output(std::ostream& s, bool human) const;

    friend std::ostream& operator<<(std::ostream& s, const BLS12381Element& x);

    static BLS12381Element generator();

    BLS12381Element negate() const;
};

BLS12381Element operator*(const Fr& a, const BLS12381Element& b);
#endif