#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMap>
#include <QMainWindow>
#include <QHostAddress>
#include "discoverydevice.h"
#include "udpbroadcast.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class BroadcastHelper;
class QUdpSocket;
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void getCurrentDevice();
    void setFolder(const QString &remotePath, const QString &localDrive);
    QString findAvailableDriveLetter();
    void listNetworkDevice();
    bool isLocalHost(const QString &ipAddr);
    bool win11_os();

private slots:
    void on_pushButtonSendMessage_clicked();

    void on_pushButtonCkearLog_clicked();

    void on_pushButtonSelect_clicked();

    void on_pushButtonShare_clicked();

    void on_pushButtonDeleteShare_clicked();

    void setNTFSPermissions(const QString& folderPath);

    void on_pushButtonNetPC_clicked();

    void on_checkBoxEnableBroad_clicked(bool checked);

    void on_pushButtonBroadcastHost_clicked();

private:
    void getNetPC();
    bool isLocalAddress(const QHostAddress &addr);

private:
    Ui::MainWindow *ui;
    QUdpSocket *udpSocket{nullptr};
    BroadcastHelper *broadcastHelper{nullptr};
    QMap<QString, QString> netNameToPath;
    DiscoveryDevice discoveryDevice;
    UDPBroadcast udpBroadCast;
};
#endif // MAINWINDOW_H
