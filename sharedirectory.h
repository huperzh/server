#ifndef SHAREDIRECTORY_H
#define SHAREDIRECTORY_H

#include <QObject>
#include <QJsonArray>

class ShareDirectory : public QObject
{
    Q_OBJECT
public:
    explicit ShareDirectory(QObject *parent = nullptr);
    const QJsonArray& getArray() const { return sharedArray; }
    bool shared(const QString &path, QString &errMsg);
    bool searchDirectories(const QString& hostName);
    /**
     * @brief 共享目录
     * @param 远程共享目录
     * @return 存在 true
     */
    void mapDevice(const QString &deviceName);
    void cancelDevice(const QString &networkPath, bool forceDisconnect = false);
    void setFolder(const QString &folderName);
    /**
     * @brief 查询共享目录是否已经存在映射
     * @param 远程共享目录
     * @return 存在 true
     */
    bool containMapped(const QString& remoteName);
    /**
     * @brief 获取本地映射的网络驱动器
     * @return 返回key 远程目录路径(\\\\hostname\\test) ， value 本地磁盘名(Y:)
     */
    QMap<QString, QString> enumMappedNetworkDrives();

signals:

private:
    QString findAvailableDriveLetter();
    bool isDriveMapped(const QString &driveLetter);

    void saveArray();
    /**
     * @brief   从路径中获取网络共享名称
     * @param   输入的路径名称
     * @return  返回网络共享名称
     */
    bool getNetName(const QString &path, QString &netname, QString &errMsg);
    /**
     * @brief
     * @param
     * @return
     */
    bool append(const QString &path);

private:
    QJsonArray sharedArray;
    QMap<QString, QString> remote2Local;
};

#endif // SHAREDIRECTORY_H
