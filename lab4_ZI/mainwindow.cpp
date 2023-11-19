#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QGraphicsScene>
#include <QGraphicsRectItem>
#include <QTransform>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QGraphicsScene *scene = new QGraphicsScene();
    scene->setBackgroundBrush(QBrush(Qt::darkGreen));
    ui->graphicsView->setScene(scene);
    ui->graphicsView->setSceneRect(0, 0, WIDTH, HEIGHT);
    ui->graphicsView->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    deck = new Deck();
    encryptor = new Encryptor();
    QPixmap cardback = deck->getCard(1);
    players[0] = new Player(deck, encryptor, 0);
    players[1] = new Player(deck, encryptor, 1);
    currentPlayerIndex = 0;
    playersCount = 2;
    playerCard1 = scene->addPixmap(players[currentPlayerIndex]->getCard1());
    playerCard1->setPos(WIDTH / 2 - 2, HEIGHT - 100);
    playerCard2 = scene->addPixmap(players[currentPlayerIndex]->getCard2());
    playerCard2->setPos(WIDTH / 2 + 140 / 2 + 2, HEIGHT - 100);

    for(int i = 0; i < 5; i++){
        bankCards[i] = scene->addPixmap(cardback);
        bankCards[i]->setPos(WIDTH * (i + 1) / 5 - 70 / 2, HEIGHT / 2 - 100 / 2);
    }
}

void MainWindow::updatePlayerCards()
{
    playerCard1->setPixmap(players[currentPlayerIndex]->getCard1());
    playerCard2->setPixmap(players[currentPlayerIndex]->getCard2());
}

void MainWindow::startDealing()
{
    int indices[52];
    for(int i = 0; i < 52; i++){
        indices[i] = i + 2;
    }
    for(int i = 0; i < playersCount; i++){
        players[i]->encryptDeck(indices);
        players[i]->shuffleDeck(indices);
    }
    int cardIndex = 0;
    for(int i = 0; i < playersCount; i++){
        players[i]->setCards(indices[cardIndex++], indices[cardIndex++], players, playersCount);
        if(players[i]->getID() == currentPlayerIndex){
            playerCard1->setPixmap(players[i]->getCard1());
            playerCard2->setPixmap(players[i]->getCard2());
        }
    }
    for(int i = 0; i < 5; i++){
        int card = indices[cardIndex++];
        for(int i = 0; i < playersCount; i++){
            card = players[i]->decryptCard(card);
        }
        bankCards[i]->setPixmap(deck->getCard(card));
    }
}

MainWindow::~MainWindow()
{
    delete ui;
    for(int i = 0; i < playersCount; i++){
        delete players[i];
    }
    delete deck;
    delete encryptor;
    delete playerCard1;
    delete playerCard2;
    for(int i = 0; i < 5; i++){
        delete bankCards[i];
    }
}

void MainWindow::on_startDealingButton_clicked()
{
    startDealing();
}

void MainWindow::on_playerSelect_currentIndexChanged(int index)
{
    currentPlayerIndex = index;
    updatePlayerCards();
}

void MainWindow::on_addPlayerButton_clicked()
{
    if(playersCount < MAX_PLAYERS){
        players[playersCount] = new Player(deck, encryptor, playersCount);
        QString text = "Игрок " + QString::number(++playersCount);
        ui->playerSelect->addItem(text);
    }
}

void MainWindow::on_deletePlayerButton_clicked()
{
    if(playersCount > 2){
        delete players[playersCount - 1];
        ui->playerSelect->removeItem(playersCount - 1);
        playersCount--;
    }
}
