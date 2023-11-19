#include "utils.hpp"
#include <chrono>
#include <stdint.h>
using namespace std;

int small_primes[] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79,	83,	89,	97, 101, 103, 107, 109,	113,
    127, 131, 137, 139,	149, 151, 157, 163,	167, 173, 179, 181,
    191, 193, 197, 199,	211, 223, 227, 229, 233, 239, 241, 251
};
const int small_primes_count = sizeof(small_primes) / sizeof(small_primes[0]);

diffie_hellman_data df_data;

int fast_pow_mod(int num, int pow, int mod) {
    int steps = floor(log2(pow));
    long long res = num;
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
    TRACE2(print_vector("U", u));
    TRACE2(print_vector("V", v));
    TRACE2(cout << endl);
    return u;
}

int inverse_mod(int num, int mod) {
    int res = extended_Euclidean(mod, num).y;
    if (res <= 0) res += mod;
    return res;
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

uint32_t generate_prime(uint32_t min, uint32_t max)
{
    RNG rng;
    uint32_t p;
    do {
        p = rng.get_random(min, max);
    } while (!is_prime(p));
    return p;
}

void Abonent::init_diffie_hellman()
{
    if (df_data.is_initialized)
        return;
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
    df_data.is_initialized = true;
}

int discrete_log(int base, int val, int mod)
{
    RNG rng;
    int m, k;
    k = m = (int)sqrt(mod) + 1;
    int* smol = new int[m];
    long long tmp = val;
    TRACE2(cout << "Smol: ");
    for (int i = 0; i < m; i++) {
        TRACE2(cout << tmp << " ");
        smol[i] = tmp;
        tmp = (tmp * base) % mod;
    }
    TRACE2(cout << endl);
    int a_m = fast_pow_mod(base, m, mod);
    long long gigant = a_m;
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

unsigned char* load_from_file(const char* file_path, size_t *size)
{
    std::ifstream ifs(file_path, std::ifstream::binary);
    if (ifs) {
        // get pointer to associated buffer object
        std::filebuf* pbuf = ifs.rdbuf();

        // get file size using buffer's members
        *size = pbuf->pubseekoff(0, ifs.end, ifs.in);
        pbuf->pubseekpos(0, ifs.in);

        // allocate memory to contain file data
        unsigned char* buffer = new unsigned char[*size];

        // get file data
        pbuf->sgetn((char*)buffer, *size);

        ifs.close();

        return buffer;
    }
    return nullptr;
}

void save_to_file(const unsigned char* data, size_t size, const char* file_path)
{
    ofstream ofs(file_path, std::ofstream::binary);
    if (ofs) {
        std::streambuf* pbuf = ofs.rdbuf();
        pbuf->sputn((char*)data, size);
        ofs.close();
    }
}

Abonent::Abonent(const char *name)
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
    //b.df_data = df_data;
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

RNG::RNG() {
    std::random_device device;
    engine.seed(std::chrono::steady_clock::now().time_since_epoch().count());
}
unsigned RNG::get_random(unsigned min, unsigned max) {
    std::uniform_int_distribution<unsigned> dist(min, max);
    return dist(engine);
}
