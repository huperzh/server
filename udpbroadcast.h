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
    void sendHostInfo(const QJsonArray &sharedDir);

signals:
    void notifyNewMessage(const QByteArray& message);
    void notifyDirectories(const QJsonObject& deviceDirectories);

public slots:
    void broadcastMessage(const QString& message);
    void readPendingMessages();
    void recvMessage(const QByteArray& message);

private:
    bool isLocalAddress(const QHostAddress &add);
    QStringList sharedDir;
};

#endif // UDPBROADCAST_H
