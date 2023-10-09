#include "lab2.hpp"

Shamir::Shamir(const char* name) {
	this->name.assign(name);
	std::cout << this->name << std::endl;
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
	TRACE(std::cout << name << "'s C * D mod (P - 1) = " << ((long long)c * d) % (p - 1) << std::endl);
}
void Shamir::send_encrypted(const char* message, size_t size, Shamir* receiver) {
	std::cout << name << " Sent message = " << message << std::endl;
	TRACE(std::cout << "Message bytes = ");
	for (size_t i = 0; i < size; i++) {
		TRACE(std::cout << std::hex << (int)message[i] << " ");
	}
	TRACE(std::cout << std::endl);
	unsigned int* x1 = new unsigned int[size];
	TRACE(std::cout << "X1 bytes = ");
	for (size_t i = 0; i < size; i++) {
		x1[i] = fast_pow_mod(message[i], c, p);
		TRACE(std::cout << std::hex << x1[i] << " ");
	}
	TRACE(std::cout << std::endl);
	receiver->receive_x1(this, x1, size);
}
void Shamir::receive_x1(Shamir* sender, unsigned int* x1, size_t size) {
	unsigned int* x2 = new unsigned int[size];
	TRACE(std::cout << "X2 bytes = ");
	for (size_t i = 0; i < size; i++) {
		x2[i] = fast_pow_mod(x1[i], c, p);
		TRACE(std::cout << std::hex << x2[i] << " ");
	}
	TRACE(std::cout << std::endl);
	sender->receive_x2(this, x2, size);
	delete[] x1;
}
void Shamir::receive_x2(Shamir* receiver, unsigned int* x2, size_t size) {
	unsigned int* x3 = new unsigned int[size];
	TRACE(std::cout << "X3 bytes = ");
	for (size_t i = 0; i < size; i++) {
		x3[i] = fast_pow_mod(x2[i], d, p);
		TRACE(std::cout << std::hex << x3[i] << " ");
	}
	TRACE(std::cout << std::endl);
	receiver->receive_x3(this, x3, size);
	delete[] x2;
}
void Shamir::receive_x3(Shamir* sender, unsigned int* x3, size_t size) {
	unsigned int* x4 = new unsigned int[size];
	TRACE(std::cout << "X4 bytes = ");
	for (size_t i = 0; i < size; i++) {
		x4[i] = fast_pow_mod(x3[i], d, p);
		TRACE(std::cout << std::hex << x4[i] << " ");
	}
	TRACE(std::cout << std::endl);
	char* message = new char[size];
	for (size_t i = 0; i < size; i++) {
		message[i] = (char)x4[i];
	}
	std::cout << name << " received message: " << message << std::endl;
	delete[] x3;
	delete[] x4;
	delete[] message;
}