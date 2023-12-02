#include "Lab5.h"

Shop::Shop()
{
	balance = 0;
}

void Shop::receive_from_customer(banknote* b, Customer* sender)
{
	if (b->number != INVALID_NUMBER) {
		Bank* bank = b->owner_bank;
		bool check = bank->check_signature(b);
		if (check) {
			std::cout << "Transaction successful" << std::endl;
			std::cout << "Shop balance before: " << std::dec << balance << std::endl;
			balance += denomination;
			std::cout << "Shop balance after: " << std::dec << balance << std::endl;
		}
		else {
			std::cout << "Invalid banknote" << std::endl;
		}
	}
}
