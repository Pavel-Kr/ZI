#pragma once

#include <iostream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <random>
#include <fstream>

#include "SHA256.h"

#define HASH_BYTES 32

#define TRACE_LEVEL 1

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

struct diffie_hellman_data {
	int g, p;
	bool is_initialized = false;
};

extern diffie_hellman_data df_data;

class Abonent {
protected:
	int secret_key;
	RNG rng;
public:
	Abonent(){}
	//diffie_hellman_data df_data;
	int public_key;
	std::string name;
	Abonent(const char *name);
	void init_diffie_hellman();
	void print_keys();
	void init_connection(Abonent& b);
	void generate_keys();
};

struct Vector3 {
	int gcd, x, y;
};

int fast_pow_mod(int num, int pow, int mod);
void swap(int* a, int* b);
void print_vector(const char* name, Vector3 v);
Vector3 extended_Euclidean(int a, int b);
int inverse_mod(int num, int mod);
uint32_t generate_prime(uint32_t min, uint32_t max);
int discrete_log(int base, int val, int mod);
unsigned char* load_from_file(const char* file_path, size_t* size);
void save_to_file(const unsigned char* data, size_t size, const char* file_path);
std::array<uint8_t, HASH_BYTES> hash(const unsigned char* data, size_t size);