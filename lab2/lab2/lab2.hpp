#pragma once
#include "utils.hpp"
#include <assert.h>

class Shamir {
	RNG rng;
	std::string name;
	int c, d;
public:
	unsigned int p;
	Shamir(const char* name);
	void init_connection(Shamir* receiver);
	void accept_connection(int p);
	void generate_cd();
	void send_encrypted(const char* message, size_t size, Shamir* receiver);
	void receive_x1(Shamir* sender, unsigned int* x1, size_t size);
	void receive_x2(Shamir* receiver, unsigned int* x2, size_t size);
	void receive_x3(Shamir* sender, unsigned int* x3, size_t size);
};

class RSA {
	RNG rng;
	std::string name;
	int p, q;
	int secret_key;
public:
	int public_key;
	int n;
	RSA(const char* name = "RSA");
	void generate_keys();
	void print_keys();
	void save_keys_to_files(const char* _public, const char* _secret);
	void load_keys_from_files(const char* _public, const char* _secret);
	int* encrypt_data(const char* data, int public_key, int n, size_t size);
	char* decrypt_data(const int* encrypted, int secret_key, int n, size_t size);
	void send_encrypted(RSA* receiver, const char* message, size_t size);
	void receive_encrypted(int* encrypted, size_t size);
	void encrypt_file(const char* file_in, const char* file_out);
	void decrypt_file(const char* file_in, const char* file_out);
};

static class Vernam {
public:
	static char* encrypt_data(const char* data, const char* key, size_t size);
	static void encrypt_file(const char* file_in, const char* file_out, const char* file_key);
	static char* generate_key(size_t size);
	static char* decrypt_data(const char* encrypted, const char* key, size_t size);
	static void decrypt_file(const char* file_in, const char* file_out, const char* file_key);
};