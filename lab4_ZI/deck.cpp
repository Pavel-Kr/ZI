#include "deck.h"

#include <QDebug>

Deck::Deck()
{
    for(int i = 1; i < 53; i++){
        QString path = "../lab4_ZI/cards/";
        path += QString::number(i);
        path += ".jpg";
        cards[i] = new QPixmap(path);
    }
    cards[0] = new QPixmap("../lab4_ZI/cards/cardback.jpg");
}

QPixmap Deck::getCard(int index){
    if (index > 53) return cards[0]->scaled(70, 100);
    int i = index - 1;
    return cards[i]->scaled(70, 100);
}
