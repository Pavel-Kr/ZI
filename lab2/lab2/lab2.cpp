#include "utils.hpp"
#include "lab2.hpp"

int main()
{
    RNG rng;
    bigint test = generate_big_prime(128);
    std::cout << test << " is prime? : " << is_prime(test, 5) << std::endl;
    //char buffer[] = "Hello, Bob!";
    /*Shamir alice("Alice");
    Shamir bob("Bob");
    alice.init_connection(&bob);
    alice.send_encrypted(buffer, sizeof(buffer), &bob);*/

    /*Abonent alice("Alice");
    Abonent bob("Bob");
    alice.init_connection(bob);
    alice.send_el_gamal_encrypted(bob, buffer, sizeof(buffer));*/

    /*RSA alice("Alice");
    RSA bob("Bob");
    alice.print_keys();
    bob.print_keys();
    alice.send_encrypted(&bob, buffer, sizeof(buffer));*/
    /*RSA rsa;
    rsa.encrypt_file("test.txt", "rsa_enc.txt");
    rsa.decrypt_file("rsa_enc.txt", "rsa_dec.txt");*/
    /*Vernam::encrypt_file("test.txt", "vernam_enc.txt", "vernam_key.txt");
    Vernam::decrypt_file("vernam_enc.txt", "vernam_dec.txt", "vernam_key.txt");*/
}
