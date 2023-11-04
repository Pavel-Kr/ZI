#include <iostream>
#include "lab2.hpp"

#define txt 0
#define pic 1

#define TYPE ElGamal
#define FILE
#define FILE_TYPE txt

int main()
{
    unsigned char buf[] = "Hello, World!";
    size_t size = sizeof(buf);

    TYPE alice("Alice");
    TYPE bob("Bob");
    TYPE eve("Eve");
#ifdef FILE
#if FILE_TYPE == txt
    alice.sign_file("test.txt", "signature.txt");
    bool check = bob.check_file_signature("test.txt", "signature.txt", alice);
#else
    alice.sign_file("Screen.png", "pic_signature.txt");
    bool check = bob.check_file_signature("Screen.png", "pic_signature.txt", alice);
#endif
    if (check) {
        std::cout << "Yes, 100% valid" << std::endl;
    }
    else {
        std::cout << "No, it's fake" << std::endl;
    }
#else
    unsigned int* signature = alice.sign_data(buf, size);
    bool check = bob.check_signature(buf, size, signature, alice);
    if (check) {
        std::cout << "Yes, 100% valid" << std::endl;
    }
    else {
        std::cout << "No, it's fake" << std::endl;
    }
#endif
}
