#ifndef SHAREDIRECTORY_H
#define SHAREDIRECTORY_H

#include <QObject>
#include <QFileInfoList>

class QTimer;
class ShareDirectory : public QObject
{
    Q_OBJECT
public:
    explicit ShareDirectory(QObject *parent = nullptr);
    void setFolder(const QString &dir);

public slots:
    void getInfoList();

signals:

private:
    QTimer *findInfoTimer{nullptr};
    QFileInfoList sharedInfoList;
};

#endif // SHAREDIRECTORY_H
