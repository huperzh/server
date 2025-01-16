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
#include <Mprapi.h>
#include <QDebug>
#include <QStringList>
#include "sddl.h"

#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Netapi32.lib")

ShareDirectory::ShareDirectory(QObject *parent)
    : QObject{parent}
{
    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [=]{
        QString hostName = QHostInfo::localHostName();
        bool ret = searchDirectories(hostName);
        if (ret) {
            timer->stop();
        }
    });

    timer->start(1000);
    enumMappedNetworkDrives();
}

#include <windows.h>
#include <aclapi.h>
#include <tchar.h>
#include <iostream>
void addEveryoneToDir(LPCTSTR path) {

    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;
    PSID pOwnerSid = NULL;
    PSID pGroupSid = NULL;
    PACL pSacl = NULL;

    // 获取指定路径的安全信息
    DWORD result = GetNamedSecurityInfo(
        path,                // 文件路径
        SE_FILE_OBJECT,      // 对象类型
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,  // 请求的安全信息
        &pOwnerSid,          // 所有者 SID
        &pGroupSid,          // 组 SID
        &pDacl,              // DACL
        &pSacl,              // SACL
        &pSD                  // 安全描述符
        );

    if (result != ERROR_SUCCESS) {
        std::wcout << L"Failed to get security info. Error: " << result << std::endl;
        DWORD error = GetLastError();
        std::wcout << L"GetLastError: " << error << std::endl;
        return;
    }

    // 获取 SID
    PSID pEveryoneSid = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

    if (!AllocateAndInitializeSid(
            &SIDAuthWorld, 1,
            SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0,
            &pEveryoneSid)) {
        std::wcout << L"Failed to initialize Everyone SID." << std::endl;
        return;
    }
    // 设置新的权限
    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

    ea.grfAccessPermissions = GENERIC_READ; // 读取权限
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.ptstrName = (LPTSTR)pEveryoneSid;

    // 创建一个新的 DACL，将 `Everyone` 添加到其中
    PACL pNewDacl = NULL;
    result = SetEntriesInAcl(1, &ea, pDacl, &pNewDacl);

    if (result != ERROR_SUCCESS) {
        std::wcout << L"Failed to set entries in ACL. Error: " << result << std::endl;
        return;
    }

    // 设置新的安全信息
    result = SetNamedSecurityInfoA(
        (LPTSTR)path,  // 文件路径
        SE_FILE_OBJECT,            // 对象类型
        DACL_SECURITY_INFORMATION, // 设置 DACL
        pOwnerSid,                 // 设置所有者
        pGroupSid,                 // 设置组
        pNewDacl,                  // 设置 DACL
        pSacl                      // 设置 SACL
        );

    if (result != ERROR_SUCCESS) {
        std::wcout << L"Failed to set security info. Error: " << result << std::endl;
        DWORD error = GetLastError();
        std::wcout << L"GetLastError: " << error << std::endl;
    } else {
        std::wcout << L"Security info set successfully!" << std::endl;
    }

    // 清理资源
    if (pSD) {
        LocalFree(pSD);
    }
    if (pEveryoneSid) {
        FreeSid(pEveryoneSid);
    }
    if (pNewDacl) {
        LocalFree(pNewDacl);
    }
}
void addEveryoneToDir1(LPCTSTR dirPath) {
    EXPLICIT_ACCESS ea = {0};
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD result;

    // Step 1: Get the current DACL
    result = GetNamedSecurityInfo(
        dirPath,
        SE_FILE_OBJECT,       // Type of object (file or directory)
        DACL_SECURITY_INFORMATION, // Get DACL
        NULL,                 // Owner
        NULL,                 // Primary group
        &pOldDACL,            // Existing DACL
        NULL,                 // SACL
        &pSD                  // Security Descriptor
        );

    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to get security info. Error: " << result << std::endl;
       // return;
    }

    // Step 2: Initialize an EXPLICIT_ACCESS structure for the new ACE
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE; // Grant read and execute permissions
    ea.grfAccessMode = GRANT_ACCESS;                         // Allow access
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;  // Inheritance
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)_T("Everyone");           // Trustee is "Everyone"

    // Step 3: Create a new ACL with the new ACE
    result = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to set entries in ACL. Error: " << result << std::endl;
        if(ERROR_FILE_NOT_FOUND == result) {
            std::cerr << "ERROR_FILE_NOT_FOUND " << result << std::endl;
        }
        if (pSD) LocalFree(pSD);
       // return;
    }

    // Step 4: Apply the new DACL to the object
    result = SetNamedSecurityInfo(
        (LPTSTR)dirPath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,      // Owner
        NULL,      // Group
        pNewDACL,  // New DACL
        NULL       // SACL
        );

    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to set security info. Error: " << result << std::endl;
    } else {
        std::cout << "Successfully added Everyone to the directory!" << std::endl;
    }

    // Cleanup
    if (pSD) LocalFree(pSD);
    if (pNewDACL) LocalFree(pNewDACL);
}

bool ShareDirectory::shared(const QString &path, QString &errMsg)
{
    QString netName;
    bool ret = getNetName(path, netName, errMsg);
    if (!ret) {
        qDebug() << "errMsg = " << errMsg;
        return false;
    }

    DWORD parm_err;
    std::wstring wShareName = path.toStdWString();
    LMSTR share = const_cast<LMSTR>(wShareName.c_str());
    const std::wstring wPackageName = netName.toStdWString();
    LMSTR lPackageName = const_cast<LMSTR>(wPackageName.c_str());
    // 设置共享信息
    SHARE_INFO_2 si = {0};  // 零初始化结构体
    si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    si.shi2_permissions = ACCESS_READ; // 权限废弃，设置为 0
    si.shi2_max_uses = -1; // 不限制用户数
    si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    si.shi2_netname = lPackageName;
    si.shi2_path = share;
    si.shi2_passwd = NULL;
    qDebug() << "shi2_path = " << path;
    qDebug() << "shi2_netname = " << netName;

    LPCSTR sddl = "D:(A;OICI;GR;;;WD)"; // Everyone (WD) 读取权限 (GR)
    PSECURITY_DESCRIPTOR pSD = NULL;

    NET_API_STATUS status = NetShareAdd(NULL, 2, (LPBYTE)&si, &parm_err);
    if (NERR_Success == status) {
        append(netName);
        // 2. 添加 Everyone 用户的权限
        // LPCTSTR shared_cts = (path.toLocal8Bit().data());
        // addEveryoneToDir(shared_cts);

        // if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
        //         sddl, SDDL_REVISION_1, &pSD, NULL)) {
        //     qDebug() << "Conversion successful!";
        //     // 在这里可以使用 pSD 作为安全描述符传递给其他 API
        //     // 例如设置文件或共享的权限

        //     // 释放内存
        //     LocalFree(pSD);
        // }
        errMsg = QString("Shared directory success, ret code :%1").arg(status);
        return true;
    } else {
        errMsg = QString("Shared directory failed, error code :%1").arg(status);
        return false;
    }
}

bool ShareDirectory::append(const QString &netname)
{
    if (sharedArray.contains(netname))
        return false;

    sharedArray.append(netname);
    return true;
}

bool ShareDirectory::searchDirectories(const QString& hostName)
{
    qDebug("Enter searchDirectories");
    qDebug() << "hostName = " << hostName;
    std::wstring wstrHostName = hostName.toStdWString();
    LMSTR share = const_cast<LMSTR>(wstrHostName.c_str());
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

void ShareDirectory::mapDevice(const QString &deviceName)
{
    qDebug("Enter mapDevice");
    QString remote = QString("\\\\%1").arg(deviceName);
    qDebug() << "remote = " <<remote;
    QDir dir(remote);
    if (!dir.exists()) {
        qDebug() << "Remote path is empty.";
        return;
    }

    auto entryList = dir.entryInfoList();
    for(const auto& dirInfo : entryList)    {
        // 检查共享目录是否已映射过
        QString path(QDir::toNativeSeparators(dirInfo.absoluteFilePath()));
        bool mapped = remote2Local.contains(path);
        if (mapped) {
            qDebug() << path << " is mapped";
            continue;
        }

        // 检查驱动器号是否已占用
        QString driveLetter = findAvailableDriveLetter();
        if (driveLetter.isEmpty()) {
            qDebug() << "No available drive letter.";
            return;
        } else {
            qDebug() << "find disk := " << driveLetter;
        }

        qDebug() << "path = " << path;
        qDebug() << "baseName = " << dirInfo.baseName();
        NETRESOURCEA nr;
        ZeroMemory(&nr, sizeof(NETRESOURCEA));
        nr.dwType = RESOURCETYPE_DISK;
        nr.lpLocalName =  driveLetter.toLatin1().data();
        nr.lpRemoteName = path.toLocal8Bit().data();
        nr.lpProvider = nullptr;
        // 调用 WNetAddConnection2A
        DWORD result = WNetAddConnection2A(&nr, nullptr, nullptr, 0);  // 默认标志为 0
        if (result == NO_ERROR) {
            remote2Local[path] = driveLetter;
            qDebug() << "Drive mapped successfully: " << driveLetter;
        } else {
            qDebug() << "Failed to map drive. Error code:" << result;
        }
    }
}

void ShareDirectory::cancelDevice(const QString &deviceName, bool forceDisconnect)
{
    qDebug("Enter mapDevice");
    QString remote = QString("\\\\%1").arg(deviceName);
    qDebug() << "remote = " <<remote;
    QDir dir(remote);
    if (!dir.exists()) {
        qDebug() << "Remote path is empty.";
        return;
    }

    auto entryList = dir.entryInfoList();
    for(const auto& dirInfo : entryList)    {
        // 检查共享目录是否已映射过
        QString path(QDir::toNativeSeparators(dirInfo.absoluteFilePath()));
        bool mapped = remote2Local.contains(path);
        if (!mapped) {
            qDebug() << path << " is not mapped";
            continue;
        }

        qDebug() << path << " is mapped" << remote2Local.value(path) ;
        DWORD dwResult = WNetCancelConnection2A(remote2Local.value(path).toStdString().c_str(), 0, forceDisconnect);
        if (NO_ERROR == dwResult) {
            remote2Local.remove(path);
            qDebug() << "Disconnected from " << path << " successfully.";
        } else {
            qDebug() << "Failed to disconnect from " << path << ". Error code: " << dwResult;
            QTimer *timer = new QTimer(this);
            connect(timer, &QTimer::timeout, this, [=](){
                static int count = 0;
                DWORD dwResult = WNetCancelConnection2A(remote2Local.value(path).toStdString().c_str(), 0, forceDisconnect);
                if (NO_ERROR == dwResult) {
                    timer->stop();
                    qDebug() << "Disconnected from " << path << " successfully." << "count = " << ++count;
                } else {
                    qDebug() << "next Failed to disconnect from " << path << ". Error code: " << dwResult;
                }
            });
        }
    }
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
    qDebug() << "pathDisk = " << pathDisk;
    QFileInfoList drives = QDir::drives();
    auto it = std::find_if(drives.begin(), drives.end(), [=](const QFileInfo& drive) {
        return drive.absolutePath().contains(pathDisk, Qt::CaseInsensitive);
    });

    if (it == drives.end()) {
        qDebug("disk is error");
    }

    int lastIndex = path.lastIndexOf(QDir::separator());
    netname = path.mid(lastIndex + 1);  // 获取当前文件夹名
    // QString name(path);
    // netname = name.replace("\\", "_", Qt::CaseInsensitive);
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

bool ShareDirectory::isDriveMapped(const QString &driveLetter) {
    // 使用Windows API 检查该盘符是否被映射
    std::string strDrive = driveLetter.toStdString();
    LPCSTR szPath = strDrive.c_str();
    DWORD dwType = GetDriveType(szPath);
    if (dwType == DRIVE_NO_ROOT_DIR) {
        // 盘符不存在 可用
        return false;
    } else if (dwType == DRIVE_REMOTE) {
        // 网络驱动器
        return true;
    } else if (dwType == DRIVE_FIXED || dwType == DRIVE_CDROM || dwType == DRIVE_RAMDISK) {
        // 本地驱动器
        return true;
    }

    return false;
}

QString ShareDirectory::findAvailableDriveLetter() {

    auto drives = QDir::drives();
    qDebug() << "drives = " << drives;
    // 从 Z: 开始尝试，找到第一个可用的驱动器号
    for (char drive = 'Z'; drive >= 'A'; --drive) {
        if (isDriveMapped(QString("%1:").arg(drive))) {
            qDebug() << drive << " disk drive is mapped";
            continue;
        }
        return QString("%1:").arg(drive);
    }
    return QString(); // 未找到可用驱动器号
}

void ShareDirectory::setFolder(const QString &folderName) {

    QString path(QDir::toNativeSeparators(folderName));
    QString driveLetter = findAvailableDriveLetter();
    qDebug() << "driveLetter = " << driveLetter;
    if (driveLetter.isEmpty()) {
        qDebug() << "No available drive letter.";
        return;
    }

    qDebug() << "path = " << path;
    // 配置 NETRESOURCE 结构体
    NETRESOURCEA nr;
    ZeroMemory(&nr, sizeof(NETRESOURCEA));
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpLocalName =  driveLetter.toLatin1().data();
    nr.lpRemoteName = QDir::toNativeSeparators(path).toLocal8Bit().data();
    nr.lpProvider = nullptr;

    // 调用 WNetAddConnection2A
    DWORD result = WNetAddConnection2A(&nr, nullptr, nullptr, 0);  // 默认标志为 0
    if (result == NO_ERROR) {
        qDebug() << "Drive mapped successfully: " << driveLetter;
    } else {
        qDebug() << "Failed to map drive. Error code:" << result;
    }
}

bool ShareDirectory::containMapped(const QString &remoteName)
{
    return remote2Local.contains(remoteName);
}

// 共享的但是没有映射驱动的目录也会被获取到
QMap<QString, QString> ShareDirectory::enumMappedNetworkDrives() {
    qDebug("Enter getMappedNetworkDrives");
    QList<QString> networkDrives;
    // 打开一个句柄，用于枚举当前用户的所有网络连接
    HANDLE hEnum;
    DWORD dwResult = WNetOpenEnumA(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, NULL, &hEnum);
    if (dwResult != NO_ERROR) {
        std::cerr << "WNetOpenEnum failed with error code: " << dwResult << std::endl;
        return QMap<QString, QString>();
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
                qDebug() << "localName = " << localName << "remoteName = " << remoteName;
                if(!localName.isEmpty()) {
                    remote2Local[remoteName] = localName;
                }
            }
        }
    }

    WNetCloseEnum(hEnum);
    return remote2Local;
}


