#ifndef DISCOVERYDEVICE_H
#define DISCOVERYDEVICE_H

#include <QObject>

class DiscoveryDevice : public QObject
{
    Q_OBJECT
public:
    explicit DiscoveryDevice(QObject *parent = nullptr);

signals:
};

#endif // DISCOVERYDEVICE_H
