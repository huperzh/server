#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMap>
#include <QMainWindow>

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

private slots:
    void on_pushButtonSendMessage_clicked();

    void on_pushButtonCkearLog_clicked();

    void on_pushButtonSelect_clicked();

    void on_pushButtonShare_clicked();

    void on_pushButtonDeleteShare_clicked();

    void setNTFSPermissions(const QString& folderPath);

    void on_pushButtonNetPC_clicked();

    void on_checkBoxEnableBroad_clicked(bool checked);

private:
    void getNetPC();

private:
    Ui::MainWindow *ui;
    QUdpSocket *socket;
    BroadcastHelper *broadcastHelper;
    QMap<QString, QString> netNameToPath;
};
#endif // MAINWINDOW_H
