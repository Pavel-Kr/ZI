#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "deck.h"
#include "player.h"
#include "ciphers.hpp"

#include <QMainWindow>
#include <QGraphicsPixmapItem>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    void updatePlayerCards();
    void startDealing();
    ~MainWindow();

private slots:
    void on_startDealingButton_clicked();

    void on_playerSelect_currentIndexChanged(int index);

    void on_addPlayerButton_clicked();

    void on_deletePlayerButton_clicked();

private:
    Ui::MainWindow *ui;
    const static int WIDTH = 800;
    const static int HEIGHT = 600;
    const static int MAX_PLAYERS = 10;
    Deck *deck;
    Encryptor *encryptor;
    QGraphicsPixmapItem *playerCard1, *playerCard2;
    QGraphicsPixmapItem *bankCards[5];
    Player *players[MAX_PLAYERS];
    int currentPlayerIndex = 0;
    int playersCount = 1;
};

#endif // MAINWINDOW_H
