#ifndef UDPBROADCAST_H
#define UDPBROADCAST_H

#include <QObject>
#include <QString>
#include <QUDPSocket>
#include <QHostInfo>
#include <QNetworkInterface>
#include <QTime>

#define PORT 37282
class UDPBroadcast : public QObject
{
private:
    Q_OBJECT
    QUdpSocket *udpSocket;
    QList<QHostAddress> broadcastList;
    void setBroadcastAddresses();

public:
    explicit UDPBroadcast(QObject *parent = 0);
    ~UDPBroadcast();
    void exit(int shared);
    // 发送广播时
    void sendSharedInfo(const QJsonArray &sharedDir, int shared = 0);
    // 客户端->服务端
    // 取消共享目录，收到广播时，客户端先取消挂载，再回传给服务端取消共享目录
    // 顺序不能反，否则挂载目录会显示叉号
    void sendToServer(const QJsonObject &obj);

signals:
    void notifyNewMessage(const QByteArray& message);
    void notifyDirectories(const QJsonObject& deviceDirectories);

public slots:
    void broadcastMessage(const QString& message);
    void readPendingMessages();
    void readMessage(const QByteArray& message);

private:
    bool isLocalAddress(const QHostAddress &add);
    QStringList sharedDir;
    QString deviceApp;
    QString messageRecv;
    QHostAddress host;
    quint16 port;
};

#endif // UDPBROADCAST_H
