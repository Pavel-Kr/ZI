#pragma once

#include <iostream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <random>
#include <fstream>

#include "bigint.h"

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

struct diffie_hellman_data {
	int g, p;
};

class Abonent {
	int secret_key;
	RNG rng;
	char* buffer;
	size_t buf_index;
public:
	diffie_hellman_data df_data;
	int public_key;
	std::string name;
	Abonent(const char *name);
	void init_diffie_hellman();
	void print_keys();
	void init_connection(Abonent& b);
	void generate_keys();
	void send_el_gamal_encrypted(Abonent& receiver, const char* message, size_t size);
	void create_buffer(size_t size);
	void receive_encrypted_symbol(int r, int e);
	void print_buffer();
	~Abonent();
};

struct Vector3 {
	int gcd, x, y;
};

struct Vector3Big {
	bigint gcd, x, y;
};

int fast_pow_mod(int num, int pow, int mod);
bigint fast_pow_mod(bigint num, bigint pow, bigint mod);
void swap(int* a, int* b);
void print_vector(const char* name, Vector3 v);
Vector3 extended_Euclidean(int a, int b);
Vector3Big extended_Euclidean(bigint a, bigint b);
int generate_prime(int min, int max);
bigint generate_big_prime(unsigned int bits);
bool is_prime(bigint big, int rounds);
int discrete_log(int base, int val, int mod);
char* load_from_file(const char* file_path, size_t* size);
void save_to_file(const char* data, size_t size, const char* file_path);