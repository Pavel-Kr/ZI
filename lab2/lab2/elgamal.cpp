#include "lab2.hpp"

ElGamal::ElGamal(const char* name) : buffer(NULL)
{
	this->name.assign(name);
}

void ElGamal::init_connection(ElGamal& b)
{
	init_diffie_hellman();
	b.df_data = df_data;
	generate_keys();
	print_keys();
	b.generate_keys();
	b.print_keys();
}

void ElGamal::send_encrypted(ElGamal& receiver, const unsigned char* message, size_t size)
{
	std::cout << name << " Sent message = " << message << std::endl;
	TRACE2(std::cout << "Message bytes = ");
	for (size_t i = 0; i < size; i++) {
		TRACE2(std::cout << std::dec << (int)message[i] << " ");
	}
	TRACE2(std::cout << std::endl);
	receiver.create_buffer(size);
	for (size_t i = 0; i < size; i++) {
		int k;
		do {
			k = rng.get_random(2, df_data.p - 2);
		} while (extended_Euclidean(k, df_data.p - 1).gcd != 1);
		TRACE2(std::cout << "K = " << k << std::endl);
		int r = fast_pow_mod(df_data.g, k, df_data.p);
		uint64_t powmod = fast_pow_mod(receiver.public_key, k, df_data.p);
		uint64_t tmp = powmod * message[i];
		TRACE2(std::cout << "tmp = " << tmp << std::endl);
		unsigned int e = tmp % df_data.p;
		TRACE2(std::cout << std::dec << "(" << r << "," << e << ") ");
		receiver.receive_encrypted_symbol(r, e);
	}
	TRACE2(std::cout << std::endl);
	receiver.print_buffer();
}

void ElGamal::create_buffer(size_t size)
{
	if (!buffer)
		buffer = new char[size];
	else {
		delete[] buffer;
		buffer = new char[size];
	}
	buf_index = 0;
}

void ElGamal::receive_encrypted_symbol(int r, int e) {
	uint64_t powmod = fast_pow_mod(r, (df_data.p - 1 - secret_key), df_data.p);
	uint64_t tmp = e * powmod;
	TRACE2(std::cout << "tmp = " << tmp << std::endl);
	unsigned int m = tmp % df_data.p;
	TRACE2(std::cout << "Received m = " << m << std::endl);
	buffer[buf_index++] = (char)m;
}

void ElGamal::print_buffer()
{
	std::cout << name << " received message: " << buffer << std::endl;
}

void ElGamal::save_keys_to_files(const char* _public, const char* _secret)
{
	int public_keys[] = { df_data.g, df_data.p, public_key };
	TRACE(std::cout << "Keys before saving: " << std::endl);
	TRACE(std::cout << "\tG: " << df_data.g << std::endl);
	TRACE(std::cout << "\tP: " << df_data.p << std::endl);
	TRACE(std::cout << "\tPublic key: " << public_key << std::endl);
	TRACE(std::cout << "\tSecret key: " << secret_key << std::endl);
	save_to_file((const unsigned char*)public_keys, 3 * sizeof(int), _public);
	save_to_file((const unsigned char*)&secret_key, sizeof(int), _secret);
}

void ElGamal::load_keys_from_files(const char* _public, const char* _secret)
{
	int* public_keys;
	int secret_key;
	size_t pub_size;
	public_keys = (int*)load_from_file(_public, &pub_size);
	assert(pub_size == 3 * sizeof(int));
	size_t sec_size;
	secret_key = *(int*)load_from_file(_secret, &sec_size);
	assert(sec_size == sizeof(int));
	this->df_data.g = public_keys[0];
	this->df_data.p = public_keys[1];
	this->public_key = public_keys[2];
	this->secret_key = secret_key;
	TRACE(std::cout << "Keys after loading: " << std::endl);
	TRACE(std::cout << "\tG: " << df_data.g << std::endl);
	TRACE(std::cout << "\tP: " << df_data.p << std::endl);
	TRACE(std::cout << "\tPublic key: " << public_key << std::endl);
	TRACE(std::cout << "\tSecret key: " << secret_key << std::endl);
}

unsigned int* ElGamal::encrypt_data(const unsigned char* data, int public_key, size_t size)
{
	unsigned int* encrypted = new unsigned int[size * 2];
	int j = 0;
	for (size_t i = 0; i < size; i++) {
		int k;
		do {
			k = rng.get_random(2, df_data.p - 2);
		} while (extended_Euclidean(k, df_data.p - 1).gcd != 1);
		TRACE2(std::cout << "K = " << k << std::endl);
		int r = fast_pow_mod(df_data.g, k, df_data.p);
		uint64_t powmod = fast_pow_mod(public_key, k, df_data.p);
		uint64_t tmp = powmod * data[i];
		unsigned int e = tmp % df_data.p;
		TRACE2(std::cout << std::dec << "(" << r << "," << e << ") ");
		encrypted[j++] = r;
		encrypted[j++] = e;
	}
	return encrypted;
}

unsigned char* ElGamal::decrypt_data(const unsigned int* encrypted, int secret_key, size_t size)
{
	unsigned char* decrypted = new unsigned char[size];
	int j = 0;
	for (int i = 0; i < size; i++) {
		int r = encrypted[j++];
		int e = encrypted[j++];
		uint64_t powmod = fast_pow_mod(r, (df_data.p - 1 - secret_key), df_data.p);
		uint64_t tmp = powmod * e;
		//std::cout << "tmp = " << tmp << std::endl;
		unsigned int m = tmp % df_data.p;
		//TRACE(std::cout << "Received m = " << m << std::endl);
		//buffer[buf_index++] = (char)m;
		decrypted[i] = (char)m;
	}
	return decrypted;
}

void ElGamal::encrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(file_in, &data_size);
	if (data) {
		unsigned int* encrypted = encrypt_data(data, public_key, data_size);
		save_to_file((const unsigned char*)encrypted, data_size * 2 * sizeof(int), file_out);
		save_keys_to_files("el_gamal_pub.txt", "el_gamal_sec.txt");
		std::cout << "File " << file_in << " successfully encrypted" << std::endl;
		delete[] encrypted;
		delete[] data;
	}
}

void ElGamal::decrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	unsigned int* encrypted = (unsigned int*)load_from_file(file_in, &data_size);
	data_size /= 2 * sizeof(int);
	if (encrypted) {
		load_keys_from_files("el_gamal_pub.txt", "el_gamal_sec.txt");
		unsigned char* decrypted = decrypt_data(encrypted, secret_key, data_size);
		save_to_file(decrypted, data_size, file_out);
		std::cout << "File " << file_in << " successfully decrypted" << std::endl;
		delete[] encrypted;
		delete[] decrypted;
	}
}

ElGamal::~ElGamal()
{
	if (buffer) delete[] buffer;
}
