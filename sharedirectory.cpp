#include "sharedirectory.h"
#include <QJsonArray>
#include <QDir>
#include <windows.h>
#include <lm.h>
#include <QTimer>
#include <QHostInfo>
#include <QFileInfoList>
#include <winnetwk.h>
#include <QDebug>
#include <QString>
#include <iostream>

#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Netapi32.lib")

ShareDirectory::ShareDirectory(QObject *parent)
    : QObject{parent}
{
    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [=]{
        QString hostName = QHostInfo::localHostName();
        bool ret = searchDir(hostName);
        if (ret) {
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
    LMSTR share = const_cast<LMSTR>(hostName.toStdWString().c_str());
    DWORD resumeHandle = 0;
    QJsonArray emptyArray;
    sharedArray.swap(emptyArray);
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
                    sharedArray.append(netname);
                    qDebug() << "share netname: " << netname  << "share pathname: " << pathname;
                }
            }
        } else {
            qDebug() << "NetShareEnum failed with error: ";
        }

        if (buffer) {
            NetApiBufferFree(buffer);
        }

    } while (resumeHandle != 0);
    return sharedArray.size();
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

QString ShareDirectory::findAvailableDriveLetter() {

    auto drives = QDir::drives();
    // 从 Z: 开始尝试，找到第一个可用的驱动器号
    for (char drive = 'Z'; drive >= 'A'; --drive) {
        auto it = std::find_if(drives.begin(), drives.end(), [=](const QFileInfo& item) {
            return item.absolutePath().contains(drive, Qt::CaseInsensitive);
        });

        if(it == drives.end()) {
            return QString("%1:").arg(drive);
        }
    }
    return QString(); // 未找到可用驱动器号
}

void ShareDirectory::setFolder(const QString &deviceName) {
    QString remote = QString("\\\\%1").arg(deviceName);
    qDebug() << "remote = " <<remote;
    QDir dir(remote);
    if (!dir.exists()) {
        qDebug() << "Remote path is empty.";
        return;
    }

    auto entryList = dir.entryInfoList();
    for(const auto& dirInfo : entryList)    {
        // 检查是否已指定驱动器号
        QString path(QDir::toNativeSeparators(dirInfo.absoluteFilePath()));
        QString driveLetter = findAvailableDriveLetter();
        qDebug() << "driveLetter = " << driveLetter;
        if (driveLetter.isEmpty()) {
            qDebug() << "No available drive letter.";
            return;
        }
        qDebug() << "path = " << path;
        qDebug() << "baseName = " << dirInfo.baseName();
        // 配置 NETRESOURCE 结构体
        NETRESOURCEA nr;
        ZeroMemory(&nr, sizeof(NETRESOURCEA));
        nr.dwType = RESOURCETYPE_DISK;
        nr.lpLocalName =  driveLetter.toLatin1().data();
        nr.lpRemoteName = QDir::toNativeSeparators(path).toLocal8Bit().data();
        nr.lpProvider = nullptr;

        continue;
        // 调用 WNetAddConnection2A
        DWORD result = WNetAddConnection2A(&nr, nullptr, nullptr, 0);  // 默认标志为 0
        if (result == NO_ERROR) {
            qDebug() << "Drive mapped successfully: " << driveLetter;
        } else {
            qDebug() << "Failed to map drive. Error code:" << result;
        }
    }
}

// QList<QString> ShareDirectory::getMappedNetworkDrives() {
//     QList<QString> networkDrives;

//     // 打开一个句柄，用于枚举当前用户的所有网络连接
//     HANDLE hEnum;
//     DWORD dwResult = WNetOpenEnumA(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, NULL, &hEnum);
//     if (dwResult != NO_ERROR) {
//         std::cerr << "WNetOpenEnum failed with error code: " << dwResult << std::endl;
//         return networkDrives; // 返回空列表
//     }

//     // 准备缓冲区来存储枚举结果
//     DWORD bufferSize = 16384; // 16KB 缓冲区
//     char buffer[16384];
//     LPNETRESOURCEA lpnr = (LPNETRESOURCEA)buffer;
//     DWORD entries = -1; // 枚举所有条目

//     while (true) {
//         ZeroMemory(buffer, bufferSize);
//         DWORD dwSize = bufferSize;
//         DWORD dwCount = entries;

//         dwResult = WNetEnumResourceA(hEnum, &dwCount, lpnr, &dwSize);
//         if (dwResult == ERROR_NO_MORE_ITEMS) {
//             break; // 没有更多条目
//         }
//         if (dwResult != NO_ERROR) {
//             std::cerr << "WNetEnumResource failed with error code: " << dwResult << std::endl;
//             break;
//         }

//         // 遍历返回的资源条目
//         for (DWORD i = 0; i < dwCount; ++i) {
//             if (lpnr[i].dwType == RESOURCETYPE_DISK) {
//                 // 添加远程路径到列表
//                 networkDrives.append(QString::fromLocal8Bit(lpnr[i].lpRemoteName));
//             }
//         }
//     }

//     WNetCloseEnum(hEnum); // 关闭枚举句柄
//     return networkDrives;
// }

#include <Windows.h>
#include <Mprapi.h>
#include <QDebug>
#include <QStringList>

QStringList ShareDirectory::getMappedDrives() {
    QStringList mappedDrives;

    // 定义用于网络资源枚举的结构
    DWORD dwResult = 0;
    HANDLE hEnum = NULL;
    LPBYTE lpBuffer = NULL;
    DWORD dwBufferSize = 16384;  // 缓冲区大小
    DWORD dwEntries = 0;
    DWORD dwResume = 0;

    // 打开网络资源枚举句柄
    dwResult = WNetOpenEnum(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, NULL, &hEnum);
    if (dwResult != NO_ERROR) {
        qDebug() << "Failed to open network resource enumeration.";
        return mappedDrives;  // 返回空列表
    }

    // 逐步枚举资源
    do {
        lpBuffer = (LPBYTE)malloc(dwBufferSize);
        if (lpBuffer == NULL) {
            qDebug() << "Memory allocation failed.";
            break;
        }

        dwResult = WNetEnumResource(hEnum, &dwEntries, lpBuffer, &dwBufferSize);
        if (dwResult == NO_ERROR) {
            // 遍历当前返回的网络资源
            for (DWORD i = 0; i < dwEntries; ++i) {
                // 转换为 NETRESOURCE 结构体
                LPNETRESOURCEA lpNetResource = (LPNETRESOURCEA)(lpBuffer + i * sizeof(NETRESOURCEA));

                if (lpNetResource->dwType == RESOURCETYPE_DISK && lpNetResource->lpLocalName != NULL) {
                    // 找到本地驱动器的路径，格式：Z: -> \\server\share
                    QString localDrive = QString::fromLatin1(lpNetResource->lpLocalName);
                    QString remotePath = QString::fromLatin1(lpNetResource->lpRemoteName);

                    // 输出驱动器字母和网络路径
                    mappedDrives.append(localDrive + " -> " + remotePath);
                }
            }
        } else {
            qDebug() << "Failed to enumerate network resources.";
        }

        free(lpBuffer);
        lpBuffer = NULL;
    } while (dwResult == ERROR_MORE_DATA);

    // 关闭枚举句柄
    WNetCloseEnum(hEnum);

    return mappedDrives;
}


// 共享的但是没有映射驱动的目录也会被获取到
QMap<QString, QString> ShareDirectory::getMappedNetworkDrives() {
    QList<QString> networkDrives;

    // 打开一个句柄，用于枚举当前用户的所有网络连接
    HANDLE hEnum;
    DWORD dwResult = WNetOpenEnumA(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, NULL, &hEnum);
    if (dwResult != NO_ERROR) {
        std::cerr << "WNetOpenEnum failed with error code: " << dwResult << std::endl;
        return QMap<QString, QString> (); // 返回空列表
    }

    // 准备缓冲区来存储枚举结果
    DWORD bufferSize = 16384; // 16KB 缓冲区
    char buffer[16384];
    LPNETRESOURCEA lpnr = (LPNETRESOURCEA)buffer;
    DWORD entries = -1; // 枚举所有条目

    // 枚举资源
    while (true) {
        ZeroMemory(buffer, bufferSize);
        DWORD dwSize = bufferSize;
        DWORD dwCount = entries;

        dwResult = WNetEnumResourceA(hEnum, &dwCount, lpnr, &dwSize);
        if (dwResult == ERROR_NO_MORE_ITEMS) {
            break; // 没有更多的条目
        }
        if (dwResult != NO_ERROR) {
            std::cerr << "WNetEnumResource failed with error code: " << dwResult << std::endl;
            break;
        }

        // drive =
        // drive = Z:
        // drive = Y:
        // drive = X:
        // drive = W:

        // 遍历返回的资源条目
        for (DWORD i = 0; i < dwCount; ++i) {
            if (lpnr[i].dwType == RESOURCETYPE_DISK) {
                // 添加远程路径到列表
                QString localName = QString::fromLocal8Bit(lpnr[i].lpLocalName);
                QString remoteName = QString::fromLocal8Bit(lpnr[i].lpRemoteName);
                if(!localName.isEmpty()) {
                    remote2Local[remoteName] = localName;
                }
            }
        }
    }

    WNetCloseEnum(hEnum);
    return remote2Local;
}


