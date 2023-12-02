#pragma once
#include <set>
#include "utils.hpp"
#include "rsa.hpp"

#define denomination 100
#define INVALID_NUMBER -1

class Bank;
class Shop;

struct banknote {
	int number;
	int bank_signature;
	Bank* owner_bank;
};

int one_way_func(int num);

class Customer
{
	RNG rng;
	int balance;
public:
	Customer();
	banknote generate_banknote(Bank* bank);
	void send_to_shop(banknote* b, Shop* shop);
	int get_balance();
	void set_balance(int new_balance);
};

class Bank
{
	RSA* rsa;
	std::set<int> used_banknotes;
	bool is_used(int number);
public:
	Bank();
	int get_public_key();
	int get_n();
	bool sign_banknote(banknote* b, Customer *cust);
	bool check_signature(banknote* b);
};

class Shop
{
	int balance;
public:
	Shop();
	void receive_from_customer(banknote* b, Customer* sender);
};
