#ifndef UDPBROADCAST_H
#define UDPBROADCAST_H

#include <QObject>
#include <QString>
#include <QUDPSocket>
#include <QHostInfo>
#include <QNetworkInterface>
#include <QTime>

class UDPBroadcast : public QObject
{
private:
    Q_OBJECT
    QUdpSocket *udpSocket;
    QString localHostName;
    QList<QHostAddress> broadcastList;
    void setBroadcastAddresses();

public:
    explicit UDPBroadcast(QObject *parent = 0);
    ~UDPBroadcast();
    void sendHostName();

signals:
    void notifyNewMessage(const QByteArray& message);

public slots:
    void broadcastMessage(const QString& message);
    void readPendingMessages();
    void recvMessage(const QByteArray& message);

private:
    bool isLocalAddress(const QHostAddress &add);
    QStringList sharedDir;
};

#endif // UDPBROADCAST_H
