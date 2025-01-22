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
    /**
     * @brief  共享当前目录
     * @param  输入 本地目录path, 设置为共享目录
     * @return 成功返回 true 否则 false
     */
    bool shared(const QString &path, QString &errMsg);
    /**
     * @brief  取消共享目录
     * @param  输入本地共享目录path
     * @return bool
     */
    bool cancel(const QString &path);
    /**
     * @brief  取消全部共享目录
     * @param  输入本地设备名称
     * @return bool
     */
    bool cancelAll();
    /**
     * @brief  查询当前共享目录列表
     * @param  输入 当前主机名称
     * @return 无
     */
    void search(const QString& hostName, int& status, bool exist = true);
    /**
     * @brief  映射网络驱动器
     * @param  输入主机名称
     * @return 无
     */
    void mapDevice(const QString &deviceName);
    /**
     * @brief  映射网络驱动器
     * @param  输入远端共享目录列表数据
     * @return 无
     */
    void mapDevice(const QJsonObject &remoteRes);
    /**
     * @brief  取消映射网络驱动器
     * @param  输入远端共享目录列表数据
     * @return bool
     */
    bool cancelDevice(const QString &networkPath, bool forceDisconnect = true);
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
