#include "Lab5.h"
#include "SHA256.h"

Customer::Customer()
{
	balance = 0;
}

int one_way_func(int num) {
	SHA256 sha;
	sha.update((const uint8_t*) & num, sizeof(int));
	std::array<uint8_t, HASH_BYTES> digest = sha.digest();
	return digest[0];
}

banknote Customer::generate_banknote(Bank *bank)
{
	banknote b;
	b.owner_bank = bank;
	int n = rng.get_random(2, bank->get_n());

	int r = generate_random_coprime(bank->get_n(), rng);
	int rd = fast_pow_mod(r, bank->get_public_key(), bank->get_n());
	int masked = mult_mod(one_way_func(n), rd, bank->get_n());
	b.number = masked;
	std::cout << "Masked number: " << masked << std::endl;
	if (bank->sign_banknote(&b, this)) {
		b.number = n;
		int inv_r = inverse_mod(r, bank->get_n());
		b.bank_signature = mult_mod(b.bank_signature, inv_r, bank->get_n());

		std::cout << "Banknote number: " << b.number << std::endl;
		std::cout << "Banknote signature: " << b.bank_signature << std::endl;
		std::cout << "Balance before: " << std::dec << balance << std::endl;
		balance -= denomination;
		std::cout << "Balance after: " << std::dec << balance << std::endl;
	}
	return b;
}

void Customer::send_to_shop(banknote* b, Shop* shop)
{
	shop->receive_from_customer(b, this);
}

int Customer::get_balance()
{
	return balance;
}

void Customer::set_balance(int new_balance)
{
	if (new_balance > 0) {
		balance = new_balance;
	}
}
