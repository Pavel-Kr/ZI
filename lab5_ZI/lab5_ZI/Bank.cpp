#include "Lab5.h"

bool Bank::is_used(int number)
{
	auto search = used_banknotes.find(number);
	return search != used_banknotes.end();
}

Bank::Bank()
{
	rsa = new RSA("Bank");
}

int Bank::get_public_key()
{
	return rsa->public_key;
}

int Bank::get_n()
{
	return rsa->n;
}

bool Bank::sign_banknote(banknote* b, Customer* cust)
{
	if (cust->get_balance() >= denomination) {
		b->bank_signature = rsa->sign_int_without_hashing(b->number);
		return true;
	}
	else {
		std::cout << "Not enough money" << std::endl;
		b->number = INVALID_NUMBER;
		return false;
	}
}

bool Bank::check_signature(banknote* b)
{
	if (one_way_func(b->number) != fast_pow_mod(b->bank_signature, rsa->public_key, rsa->n)) {
		std::cout << "Invalid signature" << std::endl;
		return false;
	}
	if (is_used(b->number)) {
		std::cout << "Banknote has been used" << std::endl;
		return false;
	}
	used_banknotes.insert(b->number);
	return true;
}
