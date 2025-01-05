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
    bool searchDir(const QString& hostName);
    void searchHost();

signals:

private:

    void saveArray();
    /**
     * @brief   获取网络共享名称, 判断是否已经存在共享的名称, 若存在相同的名称后面加_数字
     * @param   输入的路径名称
     * @return  返回网络共享名称 唯一性
     */
    bool getNetName(const QString &path, QString &netname, QString &errMsg);
    /**
     * @brief
     * @param
     * @return
     */
    bool append(const QString &path);

    QJsonArray sharedArray;
};

#endif // SHAREDIRECTORY_H
