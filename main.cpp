#include "mainwindow.h"

#include <QDebug>
#include <QApplication>

int main(int argc, char *argv[])
{
   // QString strAt = "AT+BKDZJ=PD2239C,CN-ZH,FULL_SC,V000,NULL";
    QString strAt = "";
    QString factoryMode;
    if (!strAt.isEmpty()) {
        QStringList splitAT = strAt.split("=");
        QString mode = "";
        if (splitAT.size() >= 2) {
            mode = splitAT.at(1);
            factoryMode = mode.replace(',', '_');
        }

        qDebug() << "mode = " << mode;
    }

    qDebug() << "factoryMode = " << factoryMode;
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
