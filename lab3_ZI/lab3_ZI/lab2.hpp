#pragma once
#include "utils.hpp"
#include <assert.h>

class ElGamal : Abonent {
	char* buffer;
	size_t buf_index;
public:
	ElGamal(const char* name);
	void init_connection(ElGamal& b);
	void send_encrypted(ElGamal& receiver, const unsigned char* message, size_t size);
	void create_buffer(size_t size);
	void receive_encrypted_symbol(int r, int e);
	void print_buffer();
	void save_keys_to_files(const char* _public, const char* _secret);
	void load_keys_from_files(const char* _public, const char* _secret);
	unsigned int* encrypt_data(const unsigned char* data, int public_key, size_t size);
	unsigned char* decrypt_data(const unsigned int* encrypted, int secret_key, size_t size);
	unsigned int* sign_data(const unsigned char* data, size_t size);
	bool check_signature(const unsigned char* data, size_t size, unsigned int* signature, ElGamal& sender);
	void encrypt_file(const char* file_in, const char* file_out);
	void decrypt_file(const char* file_in, const char* file_out);
	void sign_file(const char* data_file_in, const char* signature_file_out);
	bool check_file_signature(const char* data_file, const char* signature_file, ElGamal& sender);
	~ElGamal();
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
	unsigned int* encrypt_data(const unsigned char* data, int public_key, int n, size_t size);
	unsigned char* decrypt_data(const unsigned int* encrypted, size_t size);
	unsigned int* sign_data(const unsigned char* data, size_t size);
	bool check_signature(const unsigned char* data, size_t size, unsigned int* signature, RSA &sender);
	void send_encrypted(RSA* receiver, const unsigned char* message, size_t size);
	void receive_encrypted(unsigned int* encrypted, size_t size);
	void encrypt_file(const char* file_in, const char* file_out);
	void decrypt_file(const char* file_in, const char* file_out);
	void sign_file(const char* data_file_in, const char* signature_file_out);
	bool check_file_signature(const char* data_file, const char* signature_file, RSA& sender);
};

struct gost_params {
	uint16_t q;
	uint32_t p, a;
	bool initialized = false;
};

extern gost_params gost_data;

void init_gost();

class GOST {
	RNG rng;
	std::string name;
	int secret_key;
	void generate_keys();
public:
	int public_key;
	GOST(const char* name = "GOST");
	void print_keys();
	unsigned int* sign_data(const unsigned char* data, size_t size);
	bool check_signature(const unsigned char* data, size_t size, unsigned int* signature, GOST& sender);
	void sign_file(const char* data_file_in, const char* signature_file_out);
	bool check_file_signature(const char* data_file, const char* signature_file, GOST& sender);
};