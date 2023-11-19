#pragma once
#include "utils.hpp"
#include <assert.h>

class Encryptor{
private:
    RNG rng;
public:
    int P;
    Encryptor();
    int getRandom();
};
