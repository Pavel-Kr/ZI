#pragma once
#include "utils.hpp"
#include <assert.h>

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
	unsigned int* encrypt_data(const unsigned char* data, int public_key, int n, size_t size);
	unsigned char* decrypt_data(const unsigned int* encrypted, size_t size);
	unsigned int* sign_data(const unsigned char* data, size_t size);
	int sign_int_without_hashing(int n);
	bool check_signature(const unsigned char* data, size_t size, unsigned int* signature, RSA &sender);
	void send_encrypted(RSA* receiver, const unsigned char* message, size_t size);
	void receive_encrypted(unsigned int* encrypted, size_t size);
	void encrypt_file(const char* file_in, const char* file_out);
	void decrypt_file(const char* file_in, const char* file_out);
	void sign_file(const char* data_file_in, const char* signature_file_out);
	bool check_file_signature(const char* data_file, const char* signature_file, RSA& sender);
};