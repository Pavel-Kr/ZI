#include "lab2.hpp"

unsigned char* Vernam::encrypt_data(const unsigned char* data, const unsigned char* key, size_t size) {
	unsigned char* encrypted = new unsigned char[size];
	for (size_t i = 0; i < size; i++) {
		encrypted[i] = data[i] ^ key[i];
	}
	//std::cout << "Encrypted message: " << encrypted << std::endl;
	//std::cout << "Use this key to decrypt message: " << key << std::endl;
	return encrypted;
}

void Vernam::encrypt_file(const char* file_in, const char* file_out, const char* file_key)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(file_in, &data_size);
	if (data) {
		unsigned char* key = generate_key(data_size);
		unsigned char* encrypted = encrypt_data(data, key, data_size);
		save_to_file(encrypted, data_size, file_out);
		save_to_file(key, data_size, file_key);
		std::cout << "File " << file_in << " successfully encrypted" << std::endl;
		delete[] encrypted;
		delete[] key;
		delete[] data;
	}
}

unsigned char* Vernam::generate_key(size_t size)
{
	RNG rng;
	unsigned char* key = new unsigned char[size];
	for (size_t i = 0; i < size; i++) {
		key[i] = (unsigned char)rng.get_random(0, 255);
	}
	return key;
}

unsigned char* Vernam::decrypt_data(const unsigned char* encrypted, const unsigned char* key, size_t size)
{
	unsigned char* decrypted = new unsigned char[size];
	for (size_t i = 0; i < size; i++) {
		decrypted[i] = encrypted[i] ^ key[i];
	}
	//std::cout << "Decrypted message: " << decrypted << std::endl;
	return decrypted;
}

void Vernam::decrypt_file(const char* file_in, const char* file_out, const char* file_key)
{
	size_t data_size = 0;
	unsigned char* encrypted = load_from_file(file_in, &data_size);
	size_t key_size = 0;
	unsigned char* key = load_from_file(file_key, &key_size);
	assert(data_size == key_size);
	if (encrypted) {
		unsigned char* decrypted = decrypt_data(encrypted, key, data_size);
		save_to_file(decrypted, data_size, file_out);
		std::cout << "File " << file_in << " successfully decrypted" << std::endl;
		delete[] encrypted;
		delete[] key;
		delete[] decrypted;
	}
}
