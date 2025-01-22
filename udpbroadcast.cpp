#include "udpbroadcast.h"
#include <QDir>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCoreApplication>

UDPBroadcast::UDPBroadcast(QObject *parent) : QObject(parent)
{
    udpSocket = new QUdpSocket(this);
    setBroadcastAddresses();
    udpSocket->bind(QHostAddress::Any, PORT);
    connect(udpSocket, SIGNAL(readyRead()), this, SLOT(readPendingMessages()));
}

UDPBroadcast::~UDPBroadcast()
{
    delete udpSocket;
}

void UDPBroadcast::exit(int shared)
{
    QString hostName = QHostInfo::localHostName();
    deviceApp = qAppName();
    QJsonObject obj;
    QJsonArray arr;
    obj.insert("devicename", hostName);
    obj.insert("shared", shared);
    obj.insert("broadcastexit", 1);
    obj.insert("sharedirectory", arr);
    broadcastMessage(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

/**
 *  开启共享的当前工具在局域网发送广播数据
 */

void UDPBroadcast::sendSharedInfo(const QJsonArray &shareDir, int shared)
{
    QString hostName = QHostInfo::localHostName();
    deviceApp = qAppName();
    QJsonObject obj;
    obj.insert("devicename", hostName);
    obj.insert("shared", shared);
    obj.insert("broadcastexit", 0);
    obj.insert("sharedirectory", shareDir);
    //   qDebug() << "Compact = " << QJsonDocument(obj).toJson().data();
    broadcastMessage(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

void UDPBroadcast::sendToServer(const QJsonObject &obj)
{
    QJsonDocument doc(obj);
    QByteArray cancelMessage = doc.toJson();
    udpSocket->writeDatagram(cancelMessage, host, port);
}

void UDPBroadcast::readMessage(const QByteArray &message)
{
    if (messageRecv != message) {
        qDebug() << "read = " << QJsonDocument::fromJson(message).toJson().data();
    }

    messageRecv = message;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(message);
    // 检查解析是否成功
    if (jsonDoc.isObject()) {
        QJsonObject obj = jsonDoc.object();
        emit notifyDirectories(obj);
    } else {
        qDebug() << "Invalid JSON or not a JSON object!";
    }
}

void UDPBroadcast::broadcastMessage(const QString& message)
{
    // message.prepend(localHostName + "@" + QTime::currentTime().toString() + ": ");
    foreach (const QHostAddress &broadcast, broadcastList) {
        //  qDebug() << "broadcast = " << broadcast;
        int size = udpSocket->writeDatagram(message.toUtf8(), broadcast, PORT);
        if (-1 == size) {
            qDebug() << "writeDatagram error";
        } else {
            //  qDebug() << "size " << size;
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
        // 同一电脑上测试
        udpSocket->readDatagram(message.data(), message.size(), &host, &port);
        qDebug() << "host = " << host << "port = " << port << deviceApp;
        if (isLocalAddress(host)) {
            if (qAppName() != deviceApp) {
                readMessage(message);
            } else {
                deviceApp.clear();
            }
        } else {
            this->host = host;
            this->port = port;
            readMessage(message);
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
#endif
}
