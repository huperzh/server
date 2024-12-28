#ifndef DISCOVERYDEVICE_H
#define DISCOVERYDEVICE_H

#include <QObject>
#include <QFileInfoList>
#include <QHostAddress>
#include <QUdpSocket>
#include "settings.h"

class QTimer;
class DiscoveryDevice : public QObject
{
    Q_OBJECT
public:
    explicit DiscoveryDevice(QObject *parent = nullptr);
    void setFolder(const QString &dir);
    QList<QHostAddress> broadcastAddresses();
    void start(quint16 serverPort);
    void sendInfo(const QHostAddress &addr, quint16 port);
    bool isLocalAddress(const QHostAddress &addr);

public slots:
    void getInfoList();
    void refresh();

signals:
    void newHost(const QString &deviceName, const QHostAddress &addr, quint16 port);

private slots:
    void socketReadyRead();

private:
    QTimer *findInfoTimer{nullptr};
    QFileInfoList sharedInfoList;
    enum {
        DISCOVERY_PORT = 52636
    };
    QUdpSocket socket;
    quint16 serverPort;

};

#endif // DISCOVERYDEVICE_H
