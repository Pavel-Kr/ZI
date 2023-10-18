#include "lab2.hpp"

Shamir::Shamir(const char* name) {
	this->name.assign(name);
	//std::cout << this->name << std::endl;
}
void Shamir::init_connection(Shamir* receiver) {
	p = generate_prime(RNG_MIN, RNG_MAX);
	TRACE(std::cout << "P = " << p << std::endl);
	receiver->accept_connection(p);
	generate_cd();
}
void Shamir::accept_connection(int p) {
	this->p = p;
	generate_cd();
}
void Shamir::generate_cd() {
	c = rng.get_random(3, 99);
	if (c % 2 == 0) c++;
	while (extended_Euclidean(c, (p - 1)).gcd != 1)
	{
		c += 2;
	}
	TRACE(std::cout << name << "'s C = " << c << std::endl);
	d = extended_Euclidean((p - 1), c).y;
	if (d < 0) d += (p - 1);
	TRACE(std::cout << name << "'s D = " << d << std::endl);
	//TRACE2(std::cout << name << "'s C * D mod (P - 1) = " << ((long long)c * d) % (p - 1) << std::endl);
}
void Shamir::send_encrypted(const unsigned char* message, size_t size, Shamir* receiver) {
	unsigned int* encrypted = encrypt_data(message, size, receiver);
	receiver->receive_encrypted(encrypted, size);
}
void Shamir::receive_encrypted(unsigned int* encrypted, size_t size)
{
	unsigned char* message = calc_x4(encrypted, size);
	std::cout << name << " received message: " << message << std::endl;
	delete[] message;
	delete[] encrypted;
}
unsigned int* Shamir::calc_x1(const unsigned char* data, size_t size) {
	unsigned int* x1 = new unsigned int[size];
	for (size_t i = 0; i < size; i++) {
		x1[i] = fast_pow_mod(data[i], c, p);
		TRACE2(std::cout << std::hex << x1[i] << " ");
	}
	TRACE2(std::cout << std::endl);
	return x1;
}
unsigned int* Shamir::calc_x2(const unsigned int* x1, size_t size) {
	unsigned int* x2 = new unsigned int[size];
	for (size_t i = 0; i < size; i++) {
		x2[i] = fast_pow_mod(x1[i], c, p);
		TRACE2(std::cout << std::hex << x2[i] << " ");
	}
	TRACE2(std::cout << std::endl);
	return x2;
}
unsigned int* Shamir::calc_x3(const unsigned int* x2, size_t size) {
	unsigned int* x3 = new unsigned int[size];
	for (size_t i = 0; i < size; i++) {
		x3[i] = fast_pow_mod(x2[i], d, p);
		TRACE2(std::cout << std::hex << x3[i] << " ");
	}
	TRACE2(std::cout << std::endl);
	return x3;
}

unsigned char* Shamir::calc_x4(const unsigned int* x3, size_t size)
{
	unsigned char* x4 = new unsigned char[size];
	for (size_t i = 0; i < size; i++) {
		x4[i] = (unsigned char)fast_pow_mod(x3[i], d, p);
		TRACE2(std::cout << std::hex << x4[i] << " ");
	}
	TRACE2(std::cout << std::endl);
	return x4;
}

void Shamir::save_keys_to_files(const char* _public, const char* _secret)
{
	int secret_keys[] = { c, d };
	TRACE(std::cout << "Keys before saving: " << std::endl);
	TRACE(std::cout << "\tC: " << c << std::endl);
	TRACE(std::cout << "\tD: " << d << std::endl);
	TRACE(std::cout << "\tP: " << p << std::endl);
	save_to_file((const unsigned char*)&p, sizeof(int), _public);
	save_to_file((const unsigned char*)secret_keys, 2 * sizeof(int), _secret);
}

void Shamir::load_keys_from_files(const char* _public, const char* _secret)
{
	int public_key;
	int* secret_keys;
	size_t pub_size;
	public_key = *(int*)load_from_file(_public, &pub_size);
	assert(pub_size == sizeof(int));
	size_t sec_size;
	secret_keys = (int*)load_from_file(_secret, &sec_size);
	assert(sec_size == 2 * sizeof(int));
	this->c = secret_keys[0];
	this->d = secret_keys[1];
	this->p = public_key;
	TRACE(std::cout << "Keys after loading: " << std::endl);
	TRACE(std::cout << "\tC: " << c << std::endl);
	TRACE(std::cout << "\tD: " << d << std::endl);
	TRACE(std::cout << "\tP: " << p << std::endl);
}

unsigned int* Shamir::encrypt_data(const unsigned char* data, size_t size, Shamir* receiver)
{
	unsigned int* x1 = calc_x1(data, size);
	unsigned int* x2 = receiver->calc_x2(x1, size);
	unsigned int* encrypted = calc_x3(x2, size);
	delete[] x1;
	delete[] x2;
	return encrypted;
}

unsigned char* Shamir::decrypt_data(const unsigned int* encrypted, size_t size)
{
	unsigned char* decrypted = calc_x4(encrypted, size);
	return decrypted;
}

void Shamir::encrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	unsigned char* data = load_from_file(file_in, &data_size);
	if (data) {
		Shamir receiver("Shamir rcvr");
		init_connection(&receiver);
		unsigned int* encrypted = encrypt_data(data, data_size, &receiver);
		save_to_file((const unsigned char*)encrypted, data_size * sizeof(int), file_out);
		receiver.save_keys_to_files("shamir_pub.txt", "shamir_sec.txt");
		std::cout << "File " << file_in << " successfully encrypted" << std::endl;
		delete[] encrypted;
		delete[] data;
	}
}

void Shamir::decrypt_file(const char* file_in, const char* file_out)
{
	size_t data_size = 0;
	unsigned int* encrypted = (unsigned int*)load_from_file(file_in, &data_size);
	data_size /= sizeof(int);
	if (encrypted) {
		Shamir receiver("Shamir rcvr");
		receiver.load_keys_from_files("shamir_pub.txt", "shamir_sec.txt");
		unsigned char* decrypted = receiver.decrypt_data(encrypted, data_size);
		save_to_file(decrypted, data_size, file_out);
		std::cout << "File " << file_in << " successfully decrypted" << std::endl;
		delete[] encrypted;
		delete[] decrypted;
	}
}
