#include "ciphers.hpp"

Encryptor::Encryptor()
{
    do{
        int q = generate_prime(RNG_MIN / 2, RNG_MAX / 2);
        P = 2 * q + 1;
    }while(!is_prime(P));
}

int Encryptor::getRandom()
{
    return rng.get_random(1, P - 1);
}
