#include "lab2.hpp"

gost_params gost_data;

void init_gost() {
	if (gost_data.initialized)
		return;
	do {
		gost_data.q = (uint16_t)generate_prime(1 << 10, 1 << 11);
		gost_data.p = generate_prime(RNG_MIN, RNG_MAX);
	} while ((gost_data.p - 1) % gost_data.q != 0);
	std::cout << "q = " << std::hex << gost_data.q << std::endl;
	std::cout << "p = " << std::hex << gost_data.p << std::endl;
	gost_data.a = 3;
	while (fast_pow_mod(gost_data.a, gost_data.q, gost_data.p) != 1) {
		gost_data.a++;
	}
	std::cout << "a = " << std::hex << gost_data.a << std::endl;
	gost_data.initialized = true;
}

void GOST::generate_keys()
{
	secret_key = rng.get_random(1, gost_data.q - 1);
	public_key = fast_pow_mod(gost_data.a, secret_key, gost_data.p);
}

GOST::GOST(const char* name) {
	this->name.assign(name);
	init_gost();
	generate_keys();
}

void GOST::print_keys()
{
	std::cout << name << "'s public key: " << public_key << std::endl;
	std::cout << name << "'s secret key: " << secret_key << std::endl;
}

unsigned int* GOST::sign_data(const unsigned char* data, size_t size)
{
	std::array<uint8_t, HASH_BYTES> digest = hash(data, size);
	int k, r, s;
	unsigned int* signature = new unsigned int[HASH_BYTES * 2];

	for (int i = 0; i < HASH_BYTES; i++) {
	retry:
		k = rng.get_random(1, gost_data.q - 1);
		r = fast_pow_mod(gost_data.a, k, gost_data.p);
		r %= gost_data.q;
		if (r == 0) goto retry;
		s = (k * digest[i]) % gost_data.q;
		uint64_t tmp = secret_key;
		tmp *= r;
		tmp %= gost_data.q;
		s = (s + tmp) % gost_data.q;
		if (s == 0) goto retry;
		signature[2 * i] = r;
		signature[2 * i + 1] = s;
	}
	return signature;
}

bool GOST::check_signature(const unsigned char* data, size_t size, unsigned int* signature, GOST& sender)
{
	std::array<uint8_t, HASH_BYTES> digest = hash(data, size);

	for (int i = 0; i < HASH_BYTES; i++) {
		int r = signature[2 * i];
		int s = signature[2 * i + 1];
		if (r < 0 || r >= gost_data.q || s < 0 || s >= gost_data.q) {
			return false;
		}
		int inverse_h = inverse_mod(digest[i], gost_data.q);
		int64_t tmp = s;
		tmp *= inverse_h;
		int u1 = tmp % gost_data.q;
		tmp = -r;
		tmp *= inverse_h;
		int u2 = tmp % gost_data.q;
		u2 += gost_data.q;
		int au1 = fast_pow_mod(gost_data.a, u1, gost_data.p);
		int yu2 = fast_pow_mod(sender.public_key, u2, gost_data.p);
		tmp = au1;
		tmp *= yu2;
		tmp %= gost_data.p;
		int v = tmp % gost_data.q;
		if (v != r) {
			std::cout << "Difference on " << i << "th byte" << std::endl;
			return false;
		}
	}
	return true;
}

void GOST::sign_file(const char* data_file_in, const char* signature_file_out)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(data_file_in, &data_size);
	if (data) {
		unsigned int* signature = sign_data(data, data_size);
		save_to_file((const unsigned char*)signature, HASH_BYTES * sizeof(int) * 2, signature_file_out);
		std::cout << "File " << data_file_in << " successfully signed" << std::endl;
		delete[] signature;
		delete[] data;
	}
}

bool GOST::check_file_signature(const char* data_file, const char* signature_file, GOST& sender)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(data_file, &data_size);
	size_t sig_size;
	unsigned int* signature = (unsigned int*)load_from_file(signature_file, &sig_size);
	if (sig_size != HASH_BYTES * sizeof(int) * 2) {
		std::cout << "Signature has invalid size" << std::endl;
		return false;
	}
	return check_signature(data, data_size, signature, sender);
}
