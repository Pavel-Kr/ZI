#include "utils.hpp"
#include <chrono>
using namespace std;

int small_primes[] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79,	83,	89,	97, 101, 103, 107, 109,	113,
	127, 131, 137, 139,	149, 151, 157, 163,	167, 173, 179, 181,
	191, 193, 197, 199,	211, 223, 227, 229, 233, 239, 241, 251
};
const int small_primes_count = sizeof(small_primes) / sizeof(small_primes[0]);

int fast_pow_mod(int num, int pow, int mod) {
	int steps = floor(log2(pow));
	_int64 res = num;
	int result = 1;
	for (int i = 0; i <= steps; i++) {
		TRACE2(cout << "Bit: " << (pow & 1) << endl);
		if (pow % 2 == 1) {
			TRACE2(cout << "Result: ");
			TRACE2(cout << result << " * " << res << ") % " << mod << " = ");
			result = (result * res) % mod;
			TRACE2(cout << result << endl);
		}
		TRACE2(cout << "(" << res << " * " << res << ") % " << mod << " = ");
		res = (res * res) % mod;
		TRACE2(cout << res << endl);
		pow /= 2;
	}
	return result;
}

bigint fast_pow_mod(bigint num, bigint pow, bigint mod)
{
	unsigned long long steps = pow.log2();
	bigint res = num;
	bigint result = 1;
	for (unsigned long long i = 0; i <= steps; i++) {
		TRACE2(cout << "Bit: " << (pow[0] & 1) << endl);
		if (pow[0] & 1) {
			TRACE2(cout << "Result: ");
			TRACE2(cout << result << " * " << res << ") % " << mod << " = ");
			result = (result * res) % mod;
			TRACE2(cout << result << endl);
		}
		TRACE2(cout << "(" << res << " * " << res << ") % " << mod << " = ");
		res *= res;
		res %= mod;
		TRACE2(cout << res << endl);
		pow >>= 1;
	}
	return result;
}

void swap(int* a, int* b) {
	int c = *a;
	*a = *b;
	*b = c;
}

void swap(bigint* a, bigint* b) {
	bigint c = *a;
	*a = *b;
	*b = c;
}

void print_vector(const char* name, Vector3 v) {
	cout << name << " = { " << v.gcd << ", " << v.x << ", " << v.y << " }" << endl;
}

Vector3 extended_Euclidean(int a, int b) {
	if (a < b) swap(&a, &b);
	Vector3 u = { a, 1, 0 };
	Vector3 v = { b, 0, 1 };
	while (v.gcd != 0)
	{
		TRACE2(print_vector("U", u));
		TRACE2(print_vector("V", v));
		int q = u.gcd / v.gcd;
		TRACE2(cout << "q = " << q << endl);
		Vector3 t = { u.gcd % v.gcd, u.x - q * v.x, u.y - q * v.y };
		TRACE2(print_vector("T", t));
		u = v;
		v = t;
		TRACE2(cout << endl);
	}
	TRACE2(print_vector("U", u));
	TRACE2(print_vector("V", v));
	TRACE2(cout << endl);
	return u;
}

Vector3Big extended_Euclidean(bigint a, bigint b)
{
	if (a < b) swap(&a, &b);
	Vector3Big u = { a, 1, 0 };
	Vector3Big v = { b, 0, 1 };
	while (v.gcd != 0)
	{
		TRACE2(print_vector("U", u));
		TRACE2(print_vector("V", v));
		bigint q = u.gcd / v.gcd;
		TRACE2(cout << "q = " << q << endl);
		Vector3Big t = { u.gcd % v.gcd, u.x - q * v.x, u.y - q * v.y };
		TRACE2(print_vector("T", t));
		u = v;
		v = t;
		TRACE2(cout << endl);
	}
	TRACE2(print_vector("U", u));
	TRACE2(print_vector("V", v));
	TRACE2(cout << endl);
	return u;
}

bool is_prime(int p)
{
	if (p <= 1) return false;
	int b = (int)pow(p, 0.5);
	for (int i = 2; i <= b; ++i){
		if ((p % i) == 0) return false;
	}
	return true;
}

bool is_prime(bigint big, int rounds) { // big int is not prime with probability of 4**(-rounds)
	if ((big[0] & 1) == 0) return false;
	for (int i = 0; i < small_primes_count; i++) {
		if (big % small_primes[i] == 0) 
			return false;
	}
	bigint t(0);
	unsigned long long s = 0;
	bigint big_copy = big - 1;
	RNG rng;
	while ((big_copy[0] & 1) == 0)
	{
		big_copy >>= 1;
		s++;
	}
	t = big_copy;
	unsigned long long max_a = (1 << 31 - 1);
	for (int i = 0; i < rounds; i++) {
		bigint a = rng.get_big_random(2, max_a);
		bigint x = fast_pow_mod(a, t, big);
		if (x == 1 || x == (big - 1)) {
			continue;
		}
		for (unsigned long long j = 0; j < s - 1; j++) {
			x = fast_pow_mod(x, 2, big);
			if (x == 1) return false;
			else if (x == big - 1) {
				goto cont;
			}
		}
		return false;
	cont:
		continue;
	}
	return true;
}

int generate_prime(int min, int max)
{
	RNG rng;
	int p;
	do {
		p = rng.get_random(min, max);
	} while (!is_prime(p));
	return p;
}

bigint generate_big_prime(unsigned int bits)
{
	RNG rng;
	bigint p(rng, bits);
	while (!is_prime(p, 5))
	{
		/*p++;
		if (p.log2() + 1 > bits) {
			p >>= 1;
		}
		std::cout << p << std::endl;*/
		p = bigint(rng, bits);
		std::cout << p << std::endl;
	}
	return p;
}

void Abonent::init_diffie_hellman()
{
	int q;
	do {
		q = generate_prime(RNG_MIN / 2, RNG_MAX / 2);
		df_data.p = 2 * q + 1;
	} while (!is_prime(df_data.p));
	TRACE(cout << "P = " << df_data.p << endl);
	int g = 2;
	do {
		g++;
	} while (fast_pow_mod(g, q, df_data.p) == 1);
	df_data.g = g;
	TRACE(cout << "G = " << df_data.g << endl);
}

int discrete_log(int base, int val, int mod)
{
	RNG rng;
	int m, k;
	k = m = (int)sqrt(mod) + 1;
	int* smol = new int[m];
	_int64 tmp = val;
	TRACE2(cout << "Smol: ");
	for (int i = 0; i < m; i++) {
		TRACE2(cout << tmp << " ");
		smol[i] = tmp;
		tmp = (tmp * base) % mod;
	}
	TRACE2(cout << endl);
	int a_m = fast_pow_mod(base, m, mod);
	_int64 gigant = a_m;
	TRACE2(cout << "Gigachad: ");
	for (int i = 1; i <= k; i++) {
		TRACE2(cout << gigant << " ");
		for (int j = 0; j < m; j++) {
			if (gigant == smol[j]) {
				TRACE2(cout << endl);
				return i * m - j;
			}
		}
		gigant = (gigant * a_m) % mod;
	}
	TRACE2(cout << endl);
	return 0;
}

char* load_from_file(const char* file_path, size_t *size)
{
	std::ifstream ifs(file_path, std::ifstream::binary);
	if (ifs) {
		// get pointer to associated buffer object
		std::filebuf* pbuf = ifs.rdbuf();

		// get file size using buffer's members
		*size = pbuf->pubseekoff(0, ifs.end, ifs.in);
		pbuf->pubseekpos(0, ifs.in);

		// allocate memory to contain file data
		char* buffer = new char[*size];

		// get file data
		pbuf->sgetn(buffer, *size);

		ifs.close();

		return buffer;
	}
	return nullptr;
}

void save_to_file(const char* data, size_t size, const char* file_path)
{
	ofstream ofs(file_path, std::ofstream::binary);
	if (ofs) {
		std::streambuf* pbuf = ofs.rdbuf();
		pbuf->sputn(data, size);
		ofs.close();
	}
}

Abonent::Abonent(const char *name) : buffer(NULL)
{
	this->name.assign(name);
}

void Abonent::print_keys()
{
	cout << name << "'s public key: " << public_key << endl;
	cout << name << "'s secret key: " << secret_key << endl;
}

void Abonent::init_connection(Abonent& b)
{
	init_diffie_hellman();
	b.df_data = df_data;
	generate_keys();
	print_keys();
	b.generate_keys();
	b.print_keys();
}

void Abonent::generate_keys()
{
	secret_key = rng.get_random(2, df_data.p - 2);
	public_key = fast_pow_mod(df_data.g, secret_key, df_data.p);
}

void Abonent::send_el_gamal_encrypted(Abonent& receiver, const char* message, size_t size)
{
	std::cout << name << " Sent message = " << message << std::endl;
	TRACE(std::cout << "Message bytes = ");
	for (size_t i = 0; i < size; i++) {
		TRACE(std::cout << std::dec << (int)message[i] << " ");
	}
	TRACE(std::cout << std::endl);
	receiver.create_buffer(size);
	for (size_t i = 0; i < size; i++) {
		int k;
		do {
			k = rng.get_random(2, df_data.p - 2);
		} while (extended_Euclidean(k, df_data.p - 1).gcd != 1);
		TRACE(std::cout << "K = " << k << std::endl);
		int r = fast_pow_mod(df_data.g, k, df_data.p);
		uint64_t powmod = fast_pow_mod(receiver.public_key, k, df_data.p);
		uint64_t tmp = powmod * message[i];
		std::cout << "tmp = " << tmp << std::endl;
		unsigned int e = tmp % df_data.p;
		TRACE(std::cout  << std::dec << "(" << r << "," << e << ") ");
		receiver.receive_encrypted_symbol(r, e);
	}
	TRACE(std::cout << std::endl);
	receiver.print_buffer();
}

void Abonent::create_buffer(size_t size)
{
	if(!buffer)
		buffer = new char[size];
	else {
		delete[] buffer;
		buffer = new char[size];
	}
	buf_index = 0;
}

void Abonent::receive_encrypted_symbol(int r, int e) {
	uint64_t powmod = fast_pow_mod(r, (df_data.p - 1 - secret_key), df_data.p);
	uint64_t tmp = e * powmod;
	std::cout << "tmp = " << tmp << std::endl;
	unsigned int m = tmp % df_data.p;
	TRACE(std::cout << "Received m = " << m << std::endl);
	buffer[buf_index++] = (char)m;
}

void Abonent::print_buffer()
{
	std::cout << name << " received message: " << buffer << std::endl;
}

Abonent::~Abonent()
{
	if (buffer) delete[] buffer;
}
