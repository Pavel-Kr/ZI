#include "lab2.hpp"
#include <cmath>
#include <vector>

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

RSA_Big::RSA_Big(const char* name) {
	this->name.assign(name);
	generate_keys();
}

void RSA_Big::generate_keys()
{
	int bits = 128;
	p = generate_big_prime(bits);
	//std::cout << "P = " << p << std::endl;
	do {
		q = generate_big_prime(bits);
	} while (p == q);
	//std::cout << "Q = " << q << std::endl;
	
	n = p * q;
	//std::cout << "N = " << n << std::endl;
	/*bigint */phi = (p - 1) * (q - 1);
	//std::cout << "Phi    = " << phi << std::endl;
	do {
		public_key = rng.get_big_random(2, phi - 1);
		//std::cout << "Public = " << public_key << std::endl;
	} while (extended_Euclidean(public_key, phi).gcd != 1);
	//std::cout << "Public = " << public_key << std::endl;
	secret_key = extended_Euclidean(phi, public_key).y;
	if (secret_key < 0)
		secret_key += phi;
	//std::cout << "Secret = " << secret_key << std::endl;
}

void RSA_Big::print_keys()
{
	std::cout << name << "'s public key: (" << public_key << ", " << n << ")" << std::endl;
	std::cout << name << "'s secret key: " << secret_key << std::endl;
}

bool RSA_Big::test_keys()
{
	RNG rng;
	char buffer[] = "Hello, Bob!";
	bigint test(buffer, sizeof(buffer));
	bigint enc = fast_pow_mod(test, public_key, n);
	bigint dec = fast_pow_mod(enc, secret_key, n);
	if (dec == test) {
		return true;
	}
	else {
		std::cout << "Test failed" << std::endl;
		std::cout << "Test num = " << test << std::endl;
		std::cout << "Encrypted = " << enc << std::endl;
		std::cout << "Decrypted = " << dec << std::endl;
		std::cout << std::endl;
		std::cout << "P = " << p << ", is prime? : " << is_prime(p, 64) << std::endl;
		std::cout << "Q = " << q << ", is prime? : " << is_prime(q, 64) << std::endl;
		std::cout << "N = " << n << std::endl;
		std::cout << "Phi = " << phi << std::endl;
		std::cout << "Public = " << public_key << ", is coprime with phi? : " << (extended_Euclidean(public_key, phi).gcd == 1) << std::endl;
		std::cout << "Secret = " << secret_key << std::endl;
		std::cout << "Calc secret" << std::endl;
		bigint local_secret_key = extended_Euclidean(phi, public_key).y;
		std::cout << "Local secret = " << local_secret_key << std::endl;
		if (local_secret_key < 0) {
			std::cout << "Local secret is negative" << std::endl;
			local_secret_key += phi;
			std::cout << "Local secret = " << local_secret_key << std::endl;
		}
		std::cout << "(sec * pub) % phi = " << (secret_key * public_key) % phi << std::endl;
		return false;
	}
	return false;
}

unsigned int* to_int_array(std::vector<bigint> bigs, size_t *size) {
	size_t count = 0;
	for (int i = 0; i < bigs.size(); i++) {
		count += bigs[i].digits_count() + 1;
	}
	*size = count * sizeof(int);
	unsigned int* num_array = new unsigned int[*size];
	unsigned int nums = 0;
	for (int i = 0; i < bigs.size(); i++) {
		num_array[nums++] = bigs[i].digits_count();
		for (int j = bigs[i].digits_count() - 1; j >= 0; j--) {
			num_array[nums++] = bigs[i][j];
		}
	}
	return num_array;
}

std::vector<bigint> from_int_array(unsigned int* num_array, size_t size) {
	std::vector<bigint> res;
	size_t count = size / sizeof(int);
	unsigned int nums = 0;
	while (nums < count)
	{
		size_t digits = num_array[nums++];
		bigint tmp((const char*)(num_array + nums), digits * sizeof(int));
		nums += digits;
		res.push_back(tmp);
	}
	return res;
}

void RSA_Big::save_keys_to_files(const char* _public, const char* _secret)
{
	std::vector<bigint> pub;
	std::vector<bigint> sec;
	size_t pub_size;
	size_t sec_size;

	pub.push_back(public_key);
	pub.push_back(n);
	sec.push_back(secret_key);

	unsigned int* public_keys_bytes = to_int_array(pub, &pub_size);
	unsigned int* secret_key_bytes = to_int_array(sec, &sec_size);

	TRACE(std::cout << "Keys before saving: " << std::endl);
	TRACE(std::cout << "\tPublic key: " << public_key << std::endl);
	TRACE(std::cout << "\tN: " << n << std::endl);
	TRACE(std::cout << "\tSecret key: " << secret_key << std::endl);

	save_to_file((const char*)public_keys_bytes, pub_size, _public);
	save_to_file((const char*)secret_key_bytes, sec_size, _secret);
}

void RSA_Big::load_keys_from_files(const char* _public, const char* _secret)
{
	unsigned int* public_keys_bytes;
	size_t pub_size;
	public_keys_bytes = (unsigned int*)load_from_file(_public, &pub_size);
	std::vector<bigint> pub = from_int_array(public_keys_bytes, pub_size);
	public_key = pub[0];
	n = pub[1];
	unsigned int* secret_key_bytes;
	size_t sec_size;
	secret_key_bytes = (unsigned int*)load_from_file(_secret, &sec_size);
	int sk_size = secret_key_bytes[0];
	secret_key = bigint((const char*)(secret_key_bytes + 1), sk_size * sizeof(int));
	TRACE(std::cout << "Keys after loading: " << std::endl);
	TRACE(std::cout << "\tPublic key: " << public_key << std::endl);
	TRACE(std::cout << "\tN: " << n << std::endl);
	TRACE(std::cout << "\tSecret key: " << secret_key << std::endl);
}

std::vector<bigint> RSA_Big::encrypt_data(const char* data, bigint public_key, bigint n, size_t size)
{
	size_t digits_count = n.digits_count();
	std::vector<bigint> encrypted;
	int i = 0;
	while (i < size)
	{
		int offset = (size - i) < (digits_count * sizeof(int)) ? (size - i) : (digits_count - 1) * sizeof(int);
		bigint tmp(data + i, offset);
		//std::cout << "Plain text: " << tmp << std::endl;
		bigint enc = fast_pow_mod(tmp, public_key, n);
		//std::cout << "Encrypted:     " << enc << std::endl;
		encrypted.push_back(enc);
		i += offset;
	}
	return encrypted;
}


char* RSA_Big::decrypt_data(std::vector<bigint> encrypted, bigint secret_key, bigint n, size_t *size)
{
	*size = 0;
	for (int i = 0; i < encrypted.size(); i++) {
		*size += encrypted[i].digits_count() * sizeof(int);
	}
	char* decrypted = new char[*size];
	int offset = 0;
	for (int i = 0; i < encrypted.size(); i++) {
		//std::cout << "Rcv encrypted: " << encrypted[i] << std::endl;
		bigint dec = fast_pow_mod(encrypted[i], secret_key, n);
		//std::cout << "Decrypted: " << dec << std::endl;
		char* decoded = dec.as_bytes();
		for (int i = 0; i < dec.digits_count() * sizeof(int); i++) {
			if (decoded[i] != 0) {
				decrypted[offset++] = decoded[i];
			}
		}
	}
	*size = offset;
	return decrypted;
}

void RSA_Big::send_encrypted(RSA_Big* receiver, const char* message, size_t size)
{
	std::vector<bigint> encrypted = encrypt_data(message, receiver->public_key, receiver->n, size);
	receiver->receive_encrypted(encrypted);
}

void RSA_Big::receive_encrypted(std::vector<bigint> encrypted)
{
	size_t size;
	char* message = decrypt_data(encrypted, secret_key, n, &size);
	std::cout << std::dec << name << " received message: " << message << std::endl;
	delete[] message;
}

void RSA_Big::encrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	char* data = load_from_file(file_in, &data_size);
	if (data) {
		//std::cout << "Plain text from file: " << data << std::endl;
		//std::cout << "Plain text from file (hex): ";
		/*for (int i = 0; i < data_size; i++) {
			std::cout << std::hex << (int)data[i];
		}*/
		//std::cout << std::endl;
		generate_keys();
		std::vector<bigint> encrypted = encrypt_data(data, public_key, n, data_size);
		size_t enc_size;
		unsigned int* enc_arr = to_int_array(encrypted, &enc_size);
		save_to_file((const char*)enc_arr, enc_size, file_out);
		save_keys_to_files("rsa_pub.txt", "rsa_sec.txt");
		std::cout << "File " << file_in << " successfully encrypted" << std::endl;
		delete[] enc_arr;
		delete[] data;
	}
}

void RSA_Big::decrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	unsigned int* enc_arr = (unsigned int*)load_from_file(file_in, &data_size);
	if (enc_arr) {
		load_keys_from_files("rsa_pub.txt", "rsa_sec.txt");
		std::vector<bigint> encrypted = from_int_array(enc_arr, data_size);
		char* decrypted = decrypt_data(encrypted, secret_key, n, &data_size);
		save_to_file(decrypted, data_size, file_out);
		std::cout << "File " << file_in << " successfully decrypted" << std::endl;
		delete[] enc_arr;
		delete[] decrypted;
	}
}
