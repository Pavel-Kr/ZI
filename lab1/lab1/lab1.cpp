#include "utils.hpp"
using namespace std;

int main() {
	RNG rng;
	cout << "Result = " << fast_pow_mod(14, 47, 75) << endl;

	Vector3 res = extended_Euclidean(28, 19);
	print_vector("Result", res);
	init_diffie_hellman();
	Abonent a, b;
	cout << "A keys:" << endl;
	a.print_keys();
	cout << "B keys:" << endl;
	b.print_keys();

	int zab = a.generate_key(b);
	int zba = b.generate_key(a);
	cout << "Zab = " << zab << endl;
	cout << "Zba = " << zba << endl;
	if (zab == zba) cout << "Keys are equal" << endl;
	else cout << "Error!" << endl;
	int x = discrete_log(df_data.g, a.public_key, df_data.p);
	cout << "X = " << x << endl;
	int z = fast_pow_mod(b.public_key, x, df_data.p);
	cout << "Z = " << z << endl;
}