#include "udpbroadcast.h"
#include <QDir>
#include <QJsonObject>
#include <QJsonDocument>

UDPBroadcast::UDPBroadcast(QObject *parent) : QObject(parent)
{
    udpSocket = new QUdpSocket(this);
    localHostName = QHostInfo::localHostName();
    setBroadcastAddresses();
    udpSocket->bind(QHostAddress::Any, 37282);
    connect(udpSocket, SIGNAL(readyRead()), this, SLOT(readPendingMessages()));
    connect(this, SIGNAL(notifyNewMessage(const QByteArray&)), this, SLOT(recvMessage(const QByteArray&)));
}

UDPBroadcast::~UDPBroadcast()
{
    delete udpSocket;
}

void UDPBroadcast::sendHostName()
{
    QString hostName = QHostInfo::localHostName();
    QDir hostNameDir("\\\\" + hostName);
    qDebug() << "hostNameDir" << hostNameDir.path();

    qDebug() << "Host name:" << hostName;
    qDebug() << "Shared dir:" << hostNameDir.entryInfoList();
    qDebug() << "Shared dir:" << hostNameDir.entryList();

    QJsonObject obj;
    obj.insert("devicename", hostNameDir.absolutePath());
    broadcastMessage(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

void UDPBroadcast::recvMessage(const QByteArray &message)
{
    qDebug() << "message = " << message;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(message);
    // 检查解析是否成功
    if (!jsonDoc.isNull() && jsonDoc.isObject()) {
        QJsonObject jsonObject = jsonDoc.object();
        qDebug() << "devicename:" << jsonObject["devicename"].toString();
    } else {
        qDebug() << "Invalid JSON or not a JSON object!";
    }
}

void UDPBroadcast::broadcastMessage(const QString& message)
{
    // message.prepend(localHostName + "@" + QTime::currentTime().toString() + ": ");
    auto broadcastSet = broadcastList.toSet();
    foreach (const QHostAddress &broadcast, broadcastSet) {
        qDebug() << "broadcast = " << broadcast;
        int size = udpSocket->writeDatagram(message.toUtf8(), broadcast, 37282);
        if (-1 == size) {
            qDebug() << "writeDatagram error";
        } else {
            qDebug() << "size " << size;
        }
    }
}

void UDPBroadcast::readPendingMessages()
{
    while (udpSocket->hasPendingDatagrams()) {
        QByteArray message;
        message.resize(udpSocket->pendingDatagramSize());
        QHostAddress host;
        quint16 port;
        udpSocket->readDatagram(message.data(), message.size(), &host, &port);
        if (isLocalAddress(host)) {
            qDebug() << host << port;
        } else {
            emit notifyNewMessage(message);
        }
    }
}

bool UDPBroadcast::isLocalAddress(const QHostAddress &addr)
{
    foreach (const QHostAddress &address, QNetworkInterface::allAddresses()) {
        if (addr.isEqual(address))
            return true;
    }
    return false;
}

void UDPBroadcast::setBroadcastAddresses()
{
    broadcastList.append(QHostAddress::Broadcast);
#if 0
    auto allInterfaces = QNetworkInterface::allInterfaces();
    foreach (const QNetworkInterface &interface, allInterfaces) {

        bool up = interface.flags().testFlag(QNetworkInterface::IsUp);
        bool runnig = interface.flags().testFlag(QNetworkInterface::IsRunning);
        bool broadcast = interface.flags().testFlag(QNetworkInterface::CanBroadcast);
        bool noloopBack = !interface.flags().testFlag(QNetworkInterface::IsLoopBack); //
        if (up && runnig && broadcast && noloopBack) {

            auto addressEntries = interface.addressEntries();
            foreach (const QNetworkAddressEntry &address, addressEntries) {

                QHostAddress broadcast = address.broadcast();
                if (!address.broadcast().isNull() && !broadcastList.contains(broadcast)) {

                    broadcastList.append(broadcast);
                }
            }
        }
    }
#endif;
}
