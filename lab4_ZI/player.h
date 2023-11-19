#ifndef PLAYER_H
#define PLAYER_H

#include "deck.h"
#include "ciphers.hpp"

#include <QPixmap>

class Player
{
private:
    QPixmap card1, card2;
    int secret_key;
    int public_key;
    Deck *deck;
    Encryptor *encryptor;
    int id;
public:
    Player(Deck *deck, Encryptor *e, int id);
    QPixmap getCard1();
    QPixmap getCard2();
    void setCards(int index1, int index2, Player **players, int players_count);
    int getPublicKey();
    int getID();
    int encryptCard(int card);
    int decryptCard(int card);
    void encryptDeck(int *indices);
    void shuffleDeck(int *indices);
};

#endif // PLAYER_H
