#include "rsa.hpp"
#include <cmath>
#include <vector>
#include <iostream>

RSA::RSA(const char* name) {
	this->name.assign(name);
	generate_keys();
}

void RSA::generate_keys()
{
	int min = (int)floor(sqrt(RNG_MIN));
	int max = (int)floor(sqrt(RNG_MAX));
	p = generate_prime(min, max);
	q = generate_prime(min, max);
	n = p * q;
	int phi = (p - 1) * (q - 1);
	do {
		public_key = rng.get_random(2, phi - 1);
	} while (extended_Euclidean(public_key, phi).gcd != 1);
	secret_key = extended_Euclidean(phi, public_key).y;
	if (secret_key < 0)
		secret_key += phi;
}

void RSA::print_keys()
{
	std::cout << name << "'s public key: (" << public_key << ", " << n << ")" << std::endl;
	std::cout << name << "'s secret key: " << secret_key << std::endl;
}

void RSA::save_keys_to_files(const char* _public, const char* _secret)
{
	int public_keys[] = { public_key, n };
	TRACE(std::cout << "Keys before saving: " << std::endl);
	TRACE(std::cout << "\tPublic key: " << public_key << std::endl);
	TRACE(std::cout << "\tN: " << n << std::endl);
	TRACE(std::cout << "\tSecret key: " << secret_key << std::endl);
	save_to_file((const unsigned char*)public_keys, 2 * sizeof(int), _public);
	save_to_file((const unsigned char*)&secret_key, sizeof(int), _secret);
}

void RSA::load_keys_from_files(const char* _public, const char* _secret)
{
	int* public_keys;
	int secret_key;
	size_t pub_size;
	public_keys = (int*)load_from_file(_public, &pub_size);
	assert(pub_size == 2 * sizeof(int));
	size_t sec_size;
	secret_key = *(int*)load_from_file(_secret, &sec_size);
	assert(sec_size == sizeof(int));
	this->public_key = public_keys[0];
	this->n = public_keys[1];
	this->secret_key = secret_key;
	TRACE(std::cout << "Keys after loading: " << std::endl);
	TRACE(std::cout << "\tPublic key: " << public_key << std::endl);
	TRACE(std::cout << "\tN: " << n << std::endl);
	TRACE(std::cout << "\tSecret key: " << secret_key << std::endl);
}

unsigned int* RSA::encrypt_data(const unsigned char* data, int public_key, int n, size_t size)
{
	unsigned int* encrypted = new unsigned int[size];
	for (size_t i = 0; i < size; i++) {
		encrypted[i] = fast_pow_mod(data[i], public_key, n);
	}
	return encrypted;
}

bool RSA::check_signature(const unsigned char* data, size_t size, unsigned int* signature, RSA &sender)
{
	SHA256 sha;
	sha.update(data, size);
	std::array<uint8_t, HASH_BYTES> digest = sha.digest();
	std::array<uint8_t, HASH_BYTES> dec_digest;
	for (int i = 0; i < HASH_BYTES; i++) {
		dec_digest[i] = fast_pow_mod(signature[i], sender.public_key, sender.n);
		if (dec_digest[i] != digest[i]) return false;
	}
	return true;
}

unsigned int* RSA::sign_data(const unsigned char* data, size_t size)
{
	SHA256 sha;
	sha.update(data, size);
	std::array<uint8_t, HASH_BYTES> digest = sha.digest();
	unsigned int* _signed = new unsigned int[HASH_BYTES];
	for (size_t i = 0; i < HASH_BYTES; i++) {
		_signed[i] = fast_pow_mod(digest[i], secret_key, n);
	}
	return _signed;
}

int RSA::sign_int_without_hashing(int num)
{
	return fast_pow_mod(num, secret_key, n);
}

unsigned char* RSA::decrypt_data(const unsigned int* encrypted, size_t size)
{
	unsigned char* message = new unsigned char[size];
	for (size_t i = 0; i < size; i++) {
		message[i] = (unsigned char)fast_pow_mod(encrypted[i], secret_key, n);
	}
	return message;
}

void RSA::send_encrypted(RSA* receiver, const unsigned char* message, size_t size)
{
	unsigned int* encrypted = encrypt_data(message, receiver->public_key, receiver->n, size);
	receiver->receive_encrypted(encrypted, size);
}

void RSA::receive_encrypted(unsigned int* encrypted, size_t size)
{
	unsigned char* message = decrypt_data(encrypted, size);
	std::cout << name << " received message: " << message << std::endl;
	delete[] encrypted;
	delete[] message;
}

void RSA::encrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(file_in, &data_size);
	if (data) {
		unsigned int* encrypted = encrypt_data(data, public_key, n, data_size);
		save_to_file((const unsigned char*)encrypted, data_size * sizeof(int), file_out);
		save_keys_to_files("rsa_pub.txt", "rsa_sec.txt");
		std::cout << "File " << file_in << " successfully encrypted" << std::endl;
		delete[] encrypted;
		delete[] data;
	}
}

void RSA::decrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	unsigned int* encrypted = (unsigned int*)load_from_file(file_in, &data_size);
	data_size /= sizeof(int);
	if (encrypted) {
		load_keys_from_files("rsa_pub.txt", "rsa_sec.txt");
		unsigned char* decrypted = decrypt_data(encrypted, data_size);
		save_to_file(decrypted, data_size, file_out);
		std::cout << "File " << file_in << " successfully decrypted" << std::endl;
		delete[] encrypted;
		delete[] decrypted;
	}
}

void RSA::sign_file(const char* data_file_in, const char* signature_file_out)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(data_file_in, &data_size);
	if (data) {
		unsigned int* signature = sign_data(data, data_size);
		save_to_file((const unsigned char*)signature, HASH_BYTES * sizeof(int), signature_file_out);
		std::cout << "File " << data_file_in << " successfully signed" << std::endl;
		delete[] signature;
		delete[] data;
	}
}

bool RSA::check_file_signature(const char* data_file, const char* signature_file, RSA& sender)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(data_file, &data_size);
	size_t sig_size;
	unsigned int* signature = (unsigned int*)load_from_file(signature_file, &sig_size);
	if (sig_size != HASH_BYTES * sizeof(int)) {
		std::cout << "Signature has invalid size" << std::endl;
		return false;
	}
	return check_signature(data, data_size, signature, sender);
}