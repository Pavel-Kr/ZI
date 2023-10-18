#include "utils.hpp"
#include "lab2.hpp"

int main()
{
    RNG rng;
    unsigned char buffer[] = "Hello, Bob!";
    
    /*Shamir alice("Alice");
    Shamir bob("Bob");
    alice.init_connection(&bob);
    alice.send_encrypted(buffer, sizeof(buffer), &bob);

    ElGamal alice("Alice");
    ElGamal bob("Bob");
    alice.init_connection(bob);
    alice.send_encrypted(bob, buffer, sizeof(buffer));*/

    /*Shamir shamir("Shamir");
    shamir.encrypt_file("test.txt", "shamir_enc.txt");
    shamir.decrypt_file("shamir_enc.txt", "shamir_dec.txt");
    shamir.encrypt_file("Screen.png", "shamir_enc.txt");
    shamir.decrypt_file("shamir_enc.txt", "shamir_dec_pic.png");*/

    /*ElGamal el_gamal("El Gamal");
    el_gamal.encrypt_file("test.txt", "el_gamal_enc.txt");
    el_gamal.decrypt_file("el_gamal_enc.txt", "el_gamal_dec.txt");
    el_gamal.encrypt_file("Screen.png", "el_gamal_enc.txt");
    el_gamal.decrypt_file("el_gamal_enc.txt", "el_gamal_dec_pic.png");*/

    //RSA_Big rsa;
    /*RSA rsa;
    rsa.encrypt_file("Screen.png", "rsa_enc.txt");
    rsa.decrypt_file("rsa_enc.txt", "rsa_dec_pic.png");
    rsa.encrypt_file("test.txt", "rsa_enc.txt");
    rsa.decrypt_file("rsa_enc.txt", "rsa_dec.txt");*/

    /*Vernam::encrypt_file("test.txt", "vernam_enc.txt", "vernam_key.txt");
    Vernam::decrypt_file("vernam_enc.txt", "vernam_dec.txt", "vernam_key.txt");
    Vernam::encrypt_file("Screen.png", "vernam_enc_pic.txt", "vernam_key.txt");
    Vernam::decrypt_file("vernam_enc_pic.txt", "vernam_dec_pic.png", "vernam_key.txt");*/
}