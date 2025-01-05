#include "sharedirectory.h"
#include <QJsonArray>
#include <QDir>
#include <windows.h>
#include <lm.h>
#include <QTimer>
#include <QHostInfo>
#include <QFileInfoList>

#pragma comment(lib, "Netapi32.lib")

ShareDirectory::ShareDirectory(QObject *parent)
    : QObject{parent}
{
    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [=]{
        QString hostName = QHostInfo::localHostName();
        bool ret = searchDir(hostName);
        if (0 == ret) {
            timer->stop();
        }
    });

    timer->start(1000);
}

bool ShareDirectory::shared(const QString &path, QString &errMsg)
{
    QString netName;
    bool ret = getNetName(path, netName, errMsg);
    if (!ret) {
        qDebug() << "errMsg = " << errMsg;
        return false;
    }

    SHARE_INFO_2 si;
    DWORD parm_err;
    std::wstring wShareName = path.toStdWString();
    LMSTR share = const_cast<LMSTR>(wShareName.c_str());
    std::wstring wPackageName = netName.toStdWString();
    LMSTR lPackageName = const_cast<LMSTR>(wPackageName.c_str());
    // 设置共享信息
    si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    si.shi2_permissions = 0; // 权限废弃，设置为 0
    si.shi2_max_uses = -1; // 不限制用户数
    si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    si.shi2_netname = lPackageName;
    si.shi2_path = share;
    si.shi2_passwd = NULL;
    qDebug() << "shi2_path = " << path;
    qDebug() << "shi2_netname = " << netName;
    NET_API_STATUS status = NetShareAdd(NULL, 2, (LPBYTE)&si, &parm_err);
    if (NERR_Success == status) {
        append(netName);
        errMsg = QString("Shared directory success, ret code :%1").arg(status);
        return true;
    } else {
        errMsg = QString("Shared directory failed, error code :%1").arg(status);
        return false;
    }
    return true;
}

bool ShareDirectory::append(const QString &netname)
{
    if (sharedArray.contains(netname))
        return false;

    sharedArray.append(netname);
    return true;
}

bool ShareDirectory::searchDir(const QString& hostName)
{
    QDir networkDevice(hostName);
    qDebug() << networkDevice.exists();
    qDebug() << networkDevice.entryInfoList();
    auto devices = networkDevice.entryInfoList();
    for (auto device : devices) {
        qDebug() << device << ": " << device.exists();
    }

    LMSTR share = const_cast<LMSTR>(hostName.toStdWString().c_str());
    DWORD resumeHandle = 0;
    bool ret = 0;
    do {
        DWORD entriesRead = 0, totalEntries = 0;
        LPBYTE buffer = NULL;
        NET_API_STATUS status = NetShareEnum(share, 2, &buffer, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            // 处理数据
            qDebug() << "entriesRead: " << entriesRead;
            SHARE_INFO_2* shareInfo = (SHARE_INFO_2*)buffer;
            for (DWORD i = 0; i < entriesRead; i++) {
                QString netname = QString::fromStdWString(shareInfo[i].shi2_netname);
                QString pathname = QString::fromStdWString(shareInfo[i].shi2_path);
                if (!netname.isEmpty() && netname.back() != "$") {
                    append(netname);
                    qDebug() << "share netname: " << netname  << "share pathname: " << pathname;
                }
            }
        } else {
            qDebug() << "NetShareEnum failed with error: ";
            ret = -1;
            break;
        }

        if (buffer) {
            NetApiBufferFree(buffer);
        }

    } while (resumeHandle != 0);
    return ret;
}

void ShareDirectory::searchHost()
{

}

void ShareDirectory::saveArray()
{

}

bool ShareDirectory::getNetName(const QString &path, QString &netname, QString &errMsg)
{
    QFileInfo fileInfo(path);
    if (path.length() && !fileInfo.exists()) {
        errMsg = "path is not exist";
        return false;
    }

    QString pathDisk = path.at(0);
    QFileInfoList drives = QDir::drives();
    auto it = std::find_if(drives.begin(), drives.end(), [=](const QFileInfo& drive) {
        return drive.absolutePath().contains(pathDisk, Qt::CaseInsensitive);
    });

    if (it == drives.end()) {
        qDebug("disk is error");
    }

    int lastIndex = path.lastIndexOf('\\');
    netname = path.mid(lastIndex + 1);  // 获取当前文件夹名
    QString name(path);
    netname = name.replace("\\", "_", Qt::CaseInsensitive);
    qDebug() << "netname = " << netname;
    qDebug() << "sharedArray = " << sharedArray;
    qDebug() << "oldName = " << netname;
    // 遍历 sharedArray 查找是否有相同文件夹
    if (sharedArray.contains(netname)) {
        // 生成新文件名
        errMsg = "netname is exist";
        return false;
    } else {
        return true;
    }

    return true;
}

