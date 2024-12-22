#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class QUdpSocket;
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButtonSendMessage_clicked();

    void on_pushButtonCkearLog_clicked();

    void on_pushButtonSelect_clicked();

    void on_pushButtonShared_clicked();

    void on_pushButtonSharedCancel_clicked();

private:
    Ui::MainWindow *ui;
    QUdpSocket *socket;
};
#endif // MAINWINDOW_H
