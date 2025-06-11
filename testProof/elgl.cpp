#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"

int main(){
    BLS12381Element::init();

    ELGL_KeyPair keypair;
    keypair.generate();
    Plaintext m;
    Fr m_fr;
    m_fr.setByCSPRNG();
    m.set_message(m_fr);
    std::cout << "明文为：" << m.get_message() << std::endl;
    Ciphertext c;
    std::map<Fp, Fr> P_to_m;
    keypair.get_pk().encrypt(c, m);
    BLS12381Element mm;
    keypair.get_sk().decrypt(mm, c);
    std::cout << "解密后的明文为：" << m.get_message() << std::endl;
}