#pragma once

#include <iostream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <random>

#define TRACE_LEVEL 0

#if TRACE_LEVEL == 1
#define TRACE(CMD) (CMD)
#define TRACE2(CMD)
#elif TRACE_LEVEL == 2
#define TRACE(CMD) (CMD)
#define TRACE2(CMD) (CMD)
#else
#define TRACE(CMD)
#define TRACE2(CMD)
#endif // DEBUG

#define RNG_MIN 1E8
#define RNG_MAX 1E9

class RNG {
	std::mt19937 engine;
public:
	RNG();
	unsigned get_random(unsigned min, unsigned max);
};

class Abonent {
	int secret_key;
	RNG rng;
public:
	int public_key;
	Abonent();
	void print_keys();
	int generate_key(Abonent &b);
};

struct diffie_hellman_data {
	int g, p;
};

struct Vector3 {
	int gcd, x, y;
};

extern diffie_hellman_data df_data;

int fast_pow_mod(int num, int pow, int mod);
void swap(int* a, int* b);
void print_vector(const char* name, Vector3 v);
Vector3 extended_Euclidean(int a, int b);
int generate_prime();
void init_diffie_hellman(); // MUST call before any Diffie-Hellman operation
int discrete_log(int base, int val, int mod);