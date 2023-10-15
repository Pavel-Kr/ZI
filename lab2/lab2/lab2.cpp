#include "utils.hpp"
#include "lab2.hpp"

int main()
{
    RNG rng;
    //bigint test = generate_big_prime(256);
    //std::cout << test << " is prime? : " << is_prime(test, 5) << std::endl;
    char buffer[] = "Hello, Bob!";
    //bigint test(buffer, sizeof(buffer));
    //std::cout << test << std::endl;
    
    /*Shamir alice("Alice");
    Shamir bob("Bob");
    alice.init_connection(&bob);
    alice.send_encrypted(buffer, sizeof(buffer), &bob);*/

    /*Abonent alice("Alice");
    Abonent bob("Bob");
    alice.init_connection(bob);
    alice.send_el_gamal_encrypted(bob, buffer, sizeof(buffer));*/

    //RSA_Big alice("Alice");
    ////RSA_Big bob("Bob");
    //alice.print_keys();
    //alice.test_keys();
    //bob.print_keys();
    //alice.send_encrypted(&bob, buffer, sizeof(buffer));
    //bigint test(buffer, sizeof(buffer));
    /*for (int i = 0; i < sizeof(buffer); i++) {
        std::cout << std::hex << (int)buffer[i];
    }
    std::cout << std::endl;*/
    /*char* test_buf = test.as_bytes();
    std::cout << test_buf << std::endl;
    delete[] test_buf;*/
    //alice.send_encrypted(&bob, buffer, sizeof(buffer));
    RSA_Big rsa;
    rsa.encrypt_file("test.txt", "rsa_enc.txt");
    rsa.decrypt_file("rsa_enc.txt", "rsa_dec.txt");
    
    /*Vernam::encrypt_file("test.txt", "vernam_enc.txt", "vernam_key.txt");
    Vernam::decrypt_file("vernam_enc.txt", "vernam_dec.txt", "vernam_key.txt");*/
}