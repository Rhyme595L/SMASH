#pragma once



#include "emp-aby/io/mp_io_channel.h"
#include "libelgl/elgl/Ciphertext.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"
#include "libelgl/elgloffline/Exp_proof.h"
#include "libelgl/elgloffline/Exp_prover.h"
#include "emp-aby/utils.h"
#include "libelgl/elgloffline/Exp_verifier.h"

#include <string>
#include <sstream>
#include <vector>

// // Required to compile on mac, remove on ubuntu
// #ifdef __APPLE__
//     std::shared_ptr<lbcrypto::PRNG> lbcrypto::PseudoRandomNumberGenerator::m_prng = nullptr;
// #endif


static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(const std::string &in) {
    std::string out;
    int val=0, valb=-6;
    for (unsigned char c : in) {
        val = (val<<8) + c;
        valb += 8;
        while (valb>=0) {
            out.push_back(base64_chars[(val>>valb)&0x3F]);
            valb-=6;
        }
    }
    if (valb>-6) out.push_back(base64_chars[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string &in) {
    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T[base64_chars[i]] = i;
    std::string out;
    int val=0, valb=-8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            out.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}

namespace emp {
    // whaaaaat?
    #define MAX_MULT_DEPTH 10

    template <typename IO>
    class ELGL{
        private:
            ThreadPool* pool;
        public:
            ELGL_KeyPair kp;
            PRG prg;
            int party, mult_depth = 3, add_count = 100;
            MPIOChannel<IO>* io;
            int num_party;
            vector<Ciphertext> ciphertext;
            
            ELGL(int num_party, MPIOChannel<IO>* io, ThreadPool* pool, int party, int mult_depth = -1, bool keygen = true, bool mult = false, int add_count = 100){
                BLS12381Element::init();
                this->io = io;
                this->party = party;
                this->pool = pool;
                this->num_party = num_party;
                this->mult_depth = mult_depth;
                this->add_count = add_count;
                if (mult_depth == -1) {
                    if (num_party <= MAX_MULT_DEPTH) {
                        this->mult_depth = num_party;
                    }
                    else {
                        this->mult_depth = MAX_MULT_DEPTH;
                        // whaaat?
                        int num_bootstrapping_parties = floor((double)(num_party - 1) / (double)this->mult_depth);
                        this->mult_depth = ceil((double)num_party / (double)(num_bootstrapping_parties + 1));
                    }
                }else{
                    if (mult) {
                        this->mult_depth = 1;
                    }
                }
                if (keygen){
                    kp.generate();
                }
            }

            ~ELGL(){
            }

            // proof: (g, h, g^x, h^x)
            void DecProof(ELGL_PK global_pk, std::stringstream& commitment, std::stringstream& response, std::stringstream& encMap, vector<int64_t> table, unsigned table_size,vector<BLS12381Element>& EncTable_c0, vector<BLS12381Element>& EncTable_c1, ThreadPool * pool){
                ExpProof proof(global_pk, table_size);
                vector<BLS12381Element> y3;
                table.resize(table_size);
                vector<Plaintext> x(table_size);
                // convert int 64 to Plaintext
                for(size_t i = 0; i < table_size; i++){
                    
                    x[i] = Plaintext(Fr(table[i]));
                }
                EncTable_c0.resize(table_size);
                EncTable_c1.resize(table_size);
                y3.resize(table_size);
                vector<Plaintext> r1;
                r1.resize(table_size);
                for(size_t i = 0; i < table_size; i++){
                    r1[i].set_random();
                    //y1 = g^r, y2 = gpk^r
                    EncTable_c0[i] = BLS12381Element(r1[i].get_message());
                    y3[i] = global_pk.get_pk() * r1[i].get_message();
                    EncTable_c1[i] =  y3[i] + BLS12381Element(x[i].get_message());
                    EncTable_c1[i].pack(encMap);
                }
                
                // std::cout << "finish g1,y1,y2 gen" << std::endl;
                // std::cout << "prove start" << std::endl;

                ExpProver prover(proof);
                BLS12381Element pk_ = global_pk.get_pk();
                prover.NIZKPoK(proof, commitment, response, pk_, EncTable_c0, y3, r1, pool);
            }

            void DecVerify(const ELGL_PK global_pk, std::stringstream& commitment, std::stringstream& response, std::stringstream& encMap, vector<BLS12381Element>& EncTable_c0, vector<BLS12381Element>& EncTable_c1, unsigned table_size, ThreadPool * pool){
                // verify
                ExpProof proof(global_pk, table_size);
                ExpVerifier verifier(proof);
                vector<BLS12381Element> y3;
                y3.resize(table_size);
                BLS12381Element pk_ = global_pk.get_pk();
                verifier.NIZKPoK(pk_, EncTable_c0, y3, commitment, response, pool);

                for (size_t i = 0; i < table_size; i++){
                    EncTable_c1[i].unpack(encMap);
                }
            }

            template <typename T>
            void serialize_send(T& obj, int i, int j = 0, MESSAGE_TYPE mt = NORM_MSG){
                std::stringstream s;
                obj.pack(s);
                string str      = s.str();
                int string_size = str.size();
                char* c         = (char*)malloc(string_size);
                s.read(c, string_size);
                io->send_data(i, c, string_size, j, mt);
                io->flush(i, j);
                free(c);
                s.clear();
            }

            void serialize_send_(std::stringstream& s, int i, int j = 0, MESSAGE_TYPE mt = NORM_MSG){
                string str      = s.str();
                int string_size = str.size();

                char* c         = (char*)malloc(string_size);
                s.read(c, string_size);
                io->send_data(i, c, string_size, j, mt);
                io->flush(i, j);
                free(c);
                s.clear();
            }
        
        
            template <typename T>
            void serialize_sendall(T& obj, int j = 0, MESSAGE_TYPE mt = NORM_MSG){
                std::stringstream s;
                obj.pack(s);
                string str      = s.str();
                int string_size = str.size();
                char* c         = (char*)malloc(string_size);
                s.read(c, string_size);
                std::vector<std::future<void>> res;
                for (int i = 1; i <= num_party; ++i) {
                    if (i != party) {
                        res.push_back(std::async([this, i, c, string_size, j, mt]() {
                            io->send_data(i, c, string_size, j, mt);
                            io->flush(i, j);
                        }));
                    }
                }
                for (auto& fut : res)
                    fut.get();
                res.clear();
                free(c);
                s.clear();
            }

            void serialize_sendall_(std::stringstream& s, int j = 0, MESSAGE_TYPE mt = NORM_MSG) {
                string str = s.str();
                int string_size = str.size();

                std::vector<std::future<void>> res;
                for (int i = 1; i <= num_party; ++i) {
                    if (i != party) {
                        char* c = (char*)malloc(string_size + sizeof(int));
                        memcpy(c, &party, sizeof(int));
                        memcpy(c + sizeof(int), str.data(), string_size);

                        res.push_back(std::async([this, i, c, string_size, j, mt]() {
                            io->send_data(i, c, string_size + sizeof(int), j, mt);
                            io->flush(i, j);
                            free(c);
                        }));
                    }
                }

                for (auto& fut : res) fut.get();
                res.clear();
                s.clear();
            }

        void wait_for(int src){
            bool c = false;
            io->recv_bool(src, &c, 1);
            io->flush(src, 0);
        }
    
        void send_done(int dst){
            bool c = true;
            io->send_bool(dst, &c, 1, 0);
            io->flush(dst, 0);
        }
        
            template <typename T>
            void deserialize_recv(T& obj, int i, int j = 0, MESSAGE_TYPE mt = NORM_MSG) {
                std::stringstream s;
                int string_size = 0;
                char* c         = (char*)io->recv_data(i, string_size, j, mt);
                s.write(c, string_size);
                free(c);
                obj.unpack(s);
                s.clear();
            }

            void deserialize_recv_(std::stringstream& s, int i, int j = 0, MESSAGE_TYPE mt = NORM_MSG) {
                int string_size = 0;
                char* c = (char*)io->recv_data(i, string_size, j, mt);
                if (c == nullptr || string_size <= sizeof(int)) {
                    std::cerr << "[Error] Invalid data received from party " << i << std::endl;
                    return;
                }

                int sender_id = 0;
                memcpy(&sender_id, c, sizeof(int));
                {
                    s.write(c + sizeof(int), string_size - sizeof(int));
                }

                free(c);
            }

            void serialize_send_with_tag(std::stringstream& s, int i, int tag, MESSAGE_TYPE mt = NORM_MSG) {
                string str = s.str();
                int string_size = str.size();
                char* c = (char*)malloc(sizeof(int) + string_size);
                memcpy(c, &tag, sizeof(int));
                memcpy(c + sizeof(int), str.data(), string_size);
                io->send_data(i, c, sizeof(int) + string_size, 0, mt);
                io->flush(i, 0);
                free(c);
                s.clear();
            }

            void deserialize_recv_with_tag(std::stringstream& s, int i, int tag, MESSAGE_TYPE mt = NORM_MSG) {
                while (true) {
                    int string_size = 0;
                    char* c = (char*)io->recv_data(i, string_size, 0, mt);
                    if (c == nullptr || string_size < sizeof(int)) {
                        std::cerr << "[Error] Invalid data received from party " << i << std::endl;
                        free(c);
                        continue;
                    }
                    int recv_tag = 0;
                    memcpy(&recv_tag, c, sizeof(int));
                    if (recv_tag == tag) {
                        s.write(c + sizeof(int), string_size - sizeof(int));
                        free(c);
                        break;
                    } else {
                        free(c);
                        continue;
                    }
                }
                s.clear();
            }

            void serialize_sendall_with_tag(std::stringstream& s, int tag, int j = 0, MESSAGE_TYPE mt = NORM_MSG) {
                string str = s.str();
                int string_size = str.size();
                std::vector<std::future<void>> res;
                for (int i = 1; i <= num_party; ++i) {
                    if (i != party) {
                        char* c = (char*)malloc(sizeof(int) + string_size);
                        memcpy(c, &tag, sizeof(int));
                        memcpy(c + sizeof(int), str.data(), string_size);
                        res.push_back(std::async([this, i, c, string_size, j, mt]() {
                            io->send_data(i, c, sizeof(int) + string_size, j, mt);
                            io->flush(i, j);
                            free(c);
                        }));
                    }
                }
                for (auto& fut : res) fut.get();
                res.clear();
                s.clear();
            }
    };



}