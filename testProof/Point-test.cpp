#include "libelgl/elgl/BLS12381Element.h"
#include <cstdint>
#include <future>
using namespace std;
int main(){
    size_t N = 65536;
    size_t num_threads = std::thread::hardware_concurrency();
    std::cout << "Number of threads: " << num_threads << std::endl;

    BLS12381Element::init();
    BLS12381Element a(1);
    BLS12381Element b(1);
    BLS12381Element c = a + b;

    std::stringstream os;
    c.pack(os);
    a.pack(os);
    os.seekg(0);
    BLS12381Element d;
    d.unpack(os);
    if (c == d){
        cout << "Packing and unpacking works!" << endl;
    } else {
        cout << "Packing and unpacking failed!" << endl;
    }

    BLS12381Element e;
    e.unpack(os);
    if (b == e){
        cout << "Packing and unpacking works!" << endl;
    } else {
        cout << "Packing and unpacking failed!" << endl;
    }

    size_t serializedSize = c.getPoint().getSerializedByteSize();
    char buffer[serializedSize];
    cybozu::MemoryOutputStream os2(buffer, serializedSize);
    a.pack(os2);

    cybozu::MemoryInputStream is(buffer, serializedSize);
    BLS12381Element f;
    f.unpack(is);

    if (a == f){
        cout << "Packing and unpacking works!" << endl;
    } else {
        cout << "Packing and unpacking failed!" << endl;
    }


    std::cout << "test 65536 pack in stringstream" << std::endl;
    std::stringstream ss_;
    // record time
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < N * 5; i++){
        a.pack(ss_);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Time taken: " << elapsed.count() << " seconds" << std::endl;

    std::cout << "test 65536 pack in MemoryOutputStream" << std::endl;
    size_t serializedSize2 = c.getPoint().getSerializedByteSize();
    char* buffer2 = (char *)malloc(serializedSize2 * N * 5);
    cybozu::MemoryOutputStream os3(buffer2, serializedSize2 * N * 5);
    // record time
    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < N * 5; i++){
        a.pack(os3);
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Time taken: " << elapsed.count() << " seconds" << std::endl;
    return 0;
}
