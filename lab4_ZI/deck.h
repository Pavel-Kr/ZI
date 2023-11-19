#ifndef DECK_H
#define DECK_H

#include <QPixmap>

class Deck
{
private:
    QPixmap *cards[53];
public:
    Deck();
    QPixmap getCard(int index);
};

#endif // DECK_H
