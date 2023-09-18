#include "utils.hpp"
#include <chrono>
using namespace std;

diffie_hellman_data df_data;

RNG::RNG() {
	std::random_device device;
	engine.seed(chrono::steady_clock::now().time_since_epoch().count());
}
unsigned RNG::get_random(unsigned min, unsigned max) {
	std::uniform_int_distribution<unsigned> dist(min, max);
	return dist(engine);
}

int fast_pow_mod(int num, int pow, int mod) {
	int steps = floor(log2(pow));
	_int64 res = num;
	int result = 1;
	for (int i = 0; i <= steps; i++) {
		TRACE2(cout << "Bit: " << (pow & 1) << endl);
		if (pow % 2 == 1) {
			TRACE(cout << "Result: ");
			TRACE2(cout << result << " * " << res << ") % " << mod << " = ");
			result = (result * res) % mod;
			TRACE(cout << result << endl);
		}
		TRACE2(cout << "(" << res << " * " << res << ") % " << mod << " = ");
		res = (res * res) % mod;
		TRACE2(cout << res << endl);
		pow /= 2;
	}
	return result;
}

void swap(int* a, int* b) {
	int c = *a;
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
	TRACE(print_vector("U", u));
	TRACE(print_vector("V", v));
	TRACE(cout << endl);
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

int generate_prime()
{
	RNG rng;
	int p;
	do {
		p = rng.get_random(RNG_MIN / 2, RNG_MAX / 2);
	} while (!is_prime(p));
	return p;
}

void init_diffie_hellman()
{
	RNG rng;
	int q = generate_prime();
	df_data.p = 2 * q + 1;
	TRACE(cout << "P = " << df_data.p << endl);
	int g;
	do {
		g = rng.get_random(2, df_data.p - 2);
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

Abonent::Abonent()
{
	secret_key = rng.get_random(RNG_MIN, RNG_MAX);
	public_key = fast_pow_mod(df_data.g, secret_key, df_data.p);
}

void Abonent::print_keys()
{
	cout << "Public key: " << public_key << endl;
	cout << "Secret key: " << secret_key << endl;
}

int Abonent::generate_key(Abonent& b)
{
	int z = fast_pow_mod(b.public_key, secret_key, df_data.p);
	return z;
}
