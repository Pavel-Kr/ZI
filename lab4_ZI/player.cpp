#include "player.h"
#include <QDebug>

Player::Player(Deck *deck, Encryptor *e, int id)
{
    card1 = deck->getCard(1);
    card2 = deck->getCard(1);
    this->deck = deck;
    encryptor = e;
    this->id = id;

    do{
        secret_key = e->getRandom();
    }while(extended_Euclidean(secret_key, e->P - 1).gcd != 1);
    public_key = inverse_mod(secret_key, e->P - 1);
    qDebug() << "P = " << e->P;
    qDebug() << "Secret: " << secret_key;
    qDebug() << "Public: " << public_key;

    long long tmp = secret_key;
    tmp *= public_key;
    tmp %= e->P - 1;
    qDebug() << secret_key << " * " << public_key << "mod " << e->P - 1 << " = " << tmp;

    int test = 100;
    int enc = encryptCard(test);
    int dec = decryptCard(enc);
    qDebug() << "encrypted: " << enc << ", decrypted: " << dec;
}

QPixmap Player::getCard1()
{
    return card1;
}
QPixmap Player::getCard2()
{
    return card2;
}

int Player::getPublicKey()
{
    return public_key;
}

int Player::getID()
{
    return id;
}

int Player::encryptCard(int card)
{
    return fast_pow_mod(card, secret_key, encryptor->P);
}

int Player::decryptCard(int card)
{
    return fast_pow_mod(card, public_key, encryptor->P);
}

void Player::encryptDeck(int *indices)
{
    for(int i = 0; i < 52; i++){
        int tmp = encryptCard(indices[i]);
        qDebug() << "encrypted " << indices[i] << "to" <<tmp;
        indices[i] = tmp;
    }
}

void Player::shuffleDeck(int *indices)
{
    RNG rng;
    int n = 52;
    for(int i = 0; i < n - 2; i++){
        int j = rng.get_random(i, n - 1);
        int tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }
}

void Player::setCards(int index1, int index2, Player **players, int players_count)
{
    for(int i = 0; i < players_count; i++)
    {
        if(players[i]->getID() != id){
            int tmp1 = players[i]->decryptCard(index1);
            int tmp2 = players[i]->decryptCard(index2);
            qDebug() << "decrypted " << index1 << " to " << tmp1;
            qDebug() << "decrypted " << index2 << " to " << tmp2;
            index1 = tmp1;
            index2 = tmp2;
        }
    }
    index1 = decryptCard(index1);
    index2 = decryptCard(index2);
    qDebug() << "decrypted index1: " << index1;
    qDebug() << "decrypted index2: " << index2;
    card1 = deck->getCard(index1);
    card2 = deck->getCard(index2);
}
