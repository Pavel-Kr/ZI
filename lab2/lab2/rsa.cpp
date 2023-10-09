#include "lab2.hpp"

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
	save_to_file((const char*)public_keys, 2 * sizeof(int), _public);
	save_to_file((const char*)&secret_key, sizeof(int), _secret);
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

int* RSA::encrypt_data(const char* data, int public_key, int n, size_t size)
{
	int* encrypted = new int[size];
	for (size_t i = 0; i < size; i++) {
		encrypted[i] = fast_pow_mod(data[i], public_key, n);
	}
	return encrypted;
}

char* RSA::decrypt_data(const int* encrypted, int secret_key, int n, size_t size)
{
	char* message = new char[size];
	for (size_t i = 0; i < size; i++) {
		message[i] = (char)fast_pow_mod(encrypted[i], secret_key, n);
	}
	return message;
}

void RSA::send_encrypted(RSA* receiver, const char* message, size_t size)
{
	int* encrypted = encrypt_data(message, receiver->public_key, receiver->n, size);
	receiver->receive_encrypted(encrypted, size);
}

void RSA::receive_encrypted(int* encrypted, size_t size)
{
	char* message = decrypt_data(encrypted, secret_key, n, size);
	std::cout << name << " received message: " << message << std::endl;
	delete[] encrypted;
	delete[] message;
}

void RSA::encrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	char* data = load_from_file(file_in, &data_size);
	if (data) {
		generate_keys();
		int* encrypted = encrypt_data(data, public_key, n, data_size);
		save_to_file((const char*)encrypted, data_size * sizeof(int), file_out);
		save_keys_to_files("rsa_pub.txt", "rsa_sec.txt");
		std::cout << "File " << file_in << " successfully encrypted" << std::endl;
		delete[] encrypted;
		delete[] data;
	}
}

void RSA::decrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	int* encrypted = (int*)load_from_file(file_in, &data_size);
	data_size /= sizeof(int);
	if (encrypted) {
		load_keys_from_files("rsa_pub.txt", "rsa_sec.txt");
		char* decrypted = decrypt_data(encrypted, secret_key, n, data_size);
		save_to_file(decrypted, data_size, file_out);
		std::cout << "File " << file_in << " successfully decrypted" << std::endl;
		delete[] encrypted;
		delete[] decrypted;
	}
}
