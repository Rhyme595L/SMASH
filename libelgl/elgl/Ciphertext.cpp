#include "libelgl/elgl/Ciphertext.h"
void add(Ciphertext &z, const Ciphertext &x, const Ciphertext &y){
    BLS12381Element c0, c1;
    c0 = x.get_c0() + y.get_c0();
    c1 = x.get_c1() + y.get_c1();
    z = Ciphertext(c0, c1);
}
void sub(Ciphertext &z, const Ciphertext &x, const Ciphertext &y){
    BLS12381Element c0, c1;
    c0 = x.get_c0() - y.get_c0();
    c1 = x.get_c1() - y.get_c1();
    z = Ciphertext(c0, c1);
}