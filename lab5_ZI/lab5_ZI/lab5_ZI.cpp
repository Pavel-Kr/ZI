#include <iostream>
#include "Lab5.h"

int main()
{
    Bank bank;
    Customer cust;
    Shop shop;
    cust.set_balance(200);
    banknote b = cust.generate_banknote(&bank);
    cust.send_to_shop(&b, &shop);
    //cust.send_to_shop(&b, &shop);
}
