#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QUrl>
#include <QUdpSocket>
#include <QDateTime>
#include <QDebug>
#include <QNetworkInterface>
#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QUrl>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFileDialog>
#define CMD_SEND_DISP QString("[%1]# SEND ASCII TO %2:%3")
#define CMD_RECV_DISP QString("[%1]# RECV ASCII FROM %2:%3")
/*
 *  当前工具: 从服务器上获取支持的刷机包信息，本地如果没有，从接收到的广播信息中，
 *      检测局域网内其它工具的共享目录有没有需要的
 *
 */
quint16 cast_port = 520;
QHostAddress multicastAddress("239.255.30.51");
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    return;
    discoveryDevice.start(Settings::serverPort());
    udpSocket = new QUdpSocket(this);
    udpSocket->setSocketOption(QAbstractSocket::MulticastLoopbackOption, 1);
    udpSocket->setSocketOption(QAbstractSocket::MulticastTtlOption, 1);
    bool bindRet = udpSocket->bind(QHostAddress::AnyIPv4, cast_port, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    if (!bindRet) {
        qDebug() << "Bind failed:" << udpSocket->errorString();
        return;
    }

    // // 加入多播组
    // if (!udpSocket->joinMulticastGroup(multicastAddress)) {
    //     qDebug() << "Join multicast group failed:" << udpSocket->errorString();
    //     return;
    // }

    connect(udpSocket, &QUdpSocket::readyRead, this, [=](){
        while (udpSocket->hasPendingDatagrams()) {
            qint64 size = udpSocket->pendingDatagramSize();
            QByteArray data(size, 0);
            QHostAddress addr;
            quint16 port;
            udpSocket->readDatagram(data.data(), data.size(), &addr, &port);
            QJsonObject object = QJsonDocument::fromJson(data).object();
            qDebug() << "devicename: " << object.value("devicename").toString();
            bool enable(true);
            if (enable && isLocalAddress(addr))
                continue;

            qDebug() << "data = " << data;
            QString time = QDateTime::currentDateTime().toString("yyyy-mm-dd hh:mm:ss.zzz");
            QByteArray text = CMD_RECV_DISP.arg(time).arg(QHostAddress(addr.toIPv4Address()).toString()).arg(port).toLatin1();
            ui->textEditLog->append(text);
            ui->textEditLog->append(data);
            qDebug() << "Host:" << addr;  // 输出 "192.168.0.10"
            qDebug() << "Port:" << port;  // 输出 502
            QDir hostNameDir(data);
            qDebug() << "hostNameDir:" << hostNameDir << hostNameDir.exists();  // 输出 502
        }
    });

    getCurrentDevice();
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool MainWindow::isLocalHost(const QString &ipAddr)
{
    auto interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &interface : interfaces) {
        if (interface.flags().testFlag(QNetworkInterface::IsUp) &&
            interface.flags().testFlag(QNetworkInterface::IsRunning)) {
            QList<QNetworkAddressEntry> entries = interface.addressEntries();
            for (const QNetworkAddressEntry &entry : entries) {
                QHostAddress ip = entry.ip();
                if (ip.protocol() == QAbstractSocket::IPv4Protocol) {
                    if (ip.toString() == ipAddr) {
                        return true;
                    }
                }
            }
        }
    }



    return false;
}

bool MainWindow::win11_os()
{
    QString productVersion = QSysInfo::productVersion(); // Windows 10, Windows 11 等
    if (productVersion.contains("11")) {
        return true;
    }

    return false;
}

#include <QHostInfo>
void MainWindow::getCurrentDevice()
{
    QString hostName = QHostInfo::localHostName();
    QDir hostNameDir("\\\\" + hostName);
    qDebug() << "Host name:" << hostName;
    qDebug() << "Shared dir:" << hostNameDir.entryInfoList();

    QList<QHostAddress> addresses = QNetworkInterface::allAddresses();
    for (const QHostAddress &address : addresses) {
        if (!address.isLoopback()) {  // 排除回环地址
            qDebug() << "Host IP Address:" << address.toString();
        } else {
            qDebug() << "Loop IP Address:" << address.toString();
        }
    }
}

void MainWindow::on_pushButtonSendMessage_clicked()
{
    if (udpSocket) {
        QUrl url = QUrl::fromUserInput(ui->lineEditURL->text());
        QString time = QDateTime::currentDateTime().toString("yyyy-mm-dd hh:mm:ss.zzz");
        QByteArray timeMsg = CMD_SEND_DISP.arg(time).arg(url.host()).arg(url.port()).toLatin1();
        qDebug() << url.host() << url.port();
        int size = udpSocket->writeDatagram(ui->textEditSendMessage->toPlainText().toLatin1(), QHostAddress(url.host()), url.port());
        if (-1 == size) {
            qDebug() << "writeDatagram error";
        } else {
            qDebug() << "size " << size;
            ui->textEditLog->append(timeMsg + "\n" + ui->textEditSendMessage->toPlainText());
        }
    }
}

void MainWindow::on_pushButtonCkearLog_clicked()
{
    ui->textEditLog->clear();
}

#include <QUrl>
#include <QFileDialog>
void MainWindow::on_pushButtonSelect_clicked()
{
    QString path = QFileDialog::getExistingDirectory(nullptr, ui->lineEditDirShare->text()).replace("/", "\\");
    if (path.isEmpty()) {
        return;
    }

    ui->lineEditDirShare->setText(path);
    qDebug() << ui->lineEditDirShare->text();
}

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <windows.h>
#include <lm.h>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")

void MainWindow::setNTFSPermissions(const QString& folderPath) {
    PACL oldAcl = NULL, newAcl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    // 获取文件夹的现有权限
    LPCSTR path = reinterpret_cast<LPCSTR>(folderPath.toStdString().c_str());
    // DWORD dwRes = GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
    //                                    NULL, NULL, &oldAcl, NULL, &sd);
    DWORD dwRes = 0;
    if (dwRes != ERROR_SUCCESS) {
        qDebug() << "dwRes code：" << dwRes;
    }

    // 创建对 "Everyone" 的访问控制列表（ACL），赋予权限  完全控制GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    //  ea.Trustee.ptstrName = "Everyone";

    // 创建新的ACL
    dwRes = SetEntriesInAcl(1, &ea, oldAcl, &newAcl);
    if (dwRes != ERROR_SUCCESS) {
        qDebug() << "set ACL failed, code：" << dwRes;
        return;
    }

    LPSTR path1 = folderPath.toLatin1().data(); // 转换为 LPSTR
    // 设置新的文件夹权限
    // dwRes = SetNamedSecurityInfo(path1, SE_FILE_OBJECT,
    //                              DACL_SECURITY_INFORMATION, NULL, NULL, newAcl, NULL);
    if (dwRes != ERROR_SUCCESS) {
        qDebug() << "permission set error code：" << dwRes;
    } else {
        qDebug() << "permission set success:";
    }

    // release
    if (oldAcl) {
        LocalFree(oldAcl);
    }

    if (newAcl) {
        LocalFree(newAcl);
    }

    if (sd) {
        LocalFree(sd);
    }
}

#include <aclapi.h>
#include <tchar.h> // 处理宽字符和多字节字符

#include <windows.h>
#include <aclapi.h>
#include <iostream>

void setFolderOwner(const std::wstring& folderPath) {
    PSID pOwnerSid = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // 获取现有的安全描述符
    DWORD result = GetNamedSecurityInfoW(
        folderPath.c_str(),           // Unicode 字符串
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &pOwnerSid,                   // 获取所有者 SID
        NULL,                         // 不需要组 SID
        NULL,                         // DACL
        NULL,                         // SACL
        &pSD);

    if (result != ERROR_SUCCESS) {
        std::wcout << L"GetNamedSecurityInfo failed with error: " << result << std::endl;
        return;
    }

    // 获取当前用户的 SID（你可以将其替换为你想设置的管理员 SID）
    PSID pCurrentUserSid = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&SIDAuth, 1, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &pCurrentUserSid)) {
        std::wcout << L"Failed to get current user SID" << std::endl;
        LocalFree(pSD);
        return;
    }

    // 设置新的所有者
    result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(folderPath.c_str()),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        pCurrentUserSid,
        NULL,   // 不设置组 SID
        NULL,   // DACL
        NULL);  // 不设置 SACL

    if (result != ERROR_SUCCESS) {
        std::wcout << L"setFolderOwner SetNamedSecurityInfo failed with error: " << result << std::endl;
    } else {
        std::wcout << L"setFolderOwner Successfully set owner for folder: " << folderPath << std::endl;
    }

    // 清理内存
    if (pSD) LocalFree(pSD);
    if (pCurrentUserSid) FreeSid(pCurrentUserSid);
}


void setNTFSPermissions(const QString& path) {
    const std::wstring& folderPath = path.toStdWString();
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    qDebug() << folderPath;
    DWORD attributes = GetFileAttributesW(folderPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        qDebug() << "Error: Path not found or access denied.";
    } else {
        qDebug() << "Path exists and is accessible.";
    }

    // 调用 Unicode 版本的 GetNamedSecurityInfo
    DWORD result = GetNamedSecurityInfoW(
        folderPath.c_str(),           // Unicode 字符串
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &pOldDACL,
        NULL,
        &pSD);

    if (result != ERROR_SUCCESS) {
        qDebug() << "GetNamedSecurityInfo failed with error:" << result;
        return;
    }

    // 创建一个 "Everyone" ACE（访问控制条目）
    EXPLICIT_ACCESS_W ea = {};  // EXPLICIT_ACCESS
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE; // 读取和写入权限
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT; // 应用于子文件夹和文件
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.ptstrName = const_cast<LPWSTR>(L"Everyone"); // 必须是宽字符

    // 合并新的 ACE 到现有的 DACL
    result = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
    if (result != ERROR_SUCCESS) {
        qDebug() << "SetEntriesInAcl failed with error:" << result;
        LocalFree(pSD);
        return;
    }

    // 将新的 DACL 应用到文件夹
    result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(folderPath.c_str()), // 宽字符路径
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pNewDACL,
        NULL);

    if (result != ERROR_SUCCESS) {
        qDebug() << "setNTFSPermissions SetNamedSecurityInfo failed with error:" << result;
    } else {
        qDebug() << "setNTFSPermissions Successfully set permissions for folder:" << QString::fromStdWString(folderPath);
    }

    // 清理内存
    if (pSD) LocalFree(pSD);
    if (pNewDACL) LocalFree(pNewDACL);
}

#include <aclapi.h>

/**
 * net share 共享名称=文件夹路径 /grant:Everyone,full
 * 使用 net share 命令共享文件夹
 *
 */

#include <windows.h>
#include <lm.h>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")

#if 0

void MainWindow::on_pushButtonShare_clicked()
{
    QString folderPath = ui->lineEditDirShare->text();
    // setFolderOwner(folderPath.toStdWString());

    QString hostName = QHostInfo::localHostName();
    QDir hostNameDir("\\\\" + hostName);
    qDebug() << "hostNameDir = " << hostNameDir.exists();
    SHARE_INFO_2 si;
    DWORD parm_err;
    // 设置共享信息
    si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    si.shi2_permissions = 0; // 权限已被废弃，设置为 0
    si.shi2_max_uses = -1; // 不限制用户数
    si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    // 将 QString 转换为 std::wstring
    std::wstring wFolderPath = folderPath.toStdWString();
    // 使用 c_str() 获取指向内部数据的指针
    LMSTR share = const_cast<LMSTR>(wFolderPath.c_str());
    si.shi2_path = folderPath.toStdWString().data();   //  L"D:\\package";
    si.shi2_passwd = NULL;  // 共享不需要密码
    // 获取最后一个反斜杠的位置
    qDebug() << "toNativeSeparators =" << QDir::toNativeSeparators(folderPath);
    int lastIndex = folderPath.lastIndexOf('\\');
    // 提取最后一个反斜杠后的文件夹名称
    QString packageName = folderPath.mid(lastIndex + 1);
    std::wstring wPackageName = packageName.toStdWString();
    // 使用 c_str() 获取指向内部数据的指针
    LMSTR lPackageName = const_cast<LMSTR>(wPackageName.c_str());
    si.shi2_netname = lPackageName;
    // 输出结果
    qDebug() << "last folder name:" << packageName;
    // 添加共享
    NET_API_STATUS status = NetShareAdd(NULL, 2, (LPBYTE)&si, &parm_err);
    if (status == NERR_Success) {
        std::cout << "Success share add" << parm_err << std::endl;
    } else {
        std::cout << "Failed share add" << status << std::endl;
    }
    netNameToPath[packageName] = folderPath;
    qDebug() << "folderPath:" << folderPath;
    qDebug() << "last folder name:" << packageName;
    // setNTFSPermissions(folderPath);
}
#endif

void MainWindow::on_pushButtonShare_clicked()
{
    // QDir hostName("\\DESKTOP-FNNNJ3M");
    // setFolder(hostName.absoluteFilePath(ui->lineEditDirShare->text()), "Z:");
    // return;
    SHARE_INFO_2 si;
    DWORD parm_err;
    // 设置共享信息
    si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    si.shi2_permissions = 0; // 权限已被废弃，设置为 0
    si.shi2_max_uses = -1; // 不限制用户数
    si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    QString dir(ui->lineEditDirShare->text());
    std::wstring wShareName = dir.toStdWString();
    LMSTR share = const_cast<LMSTR>(wShareName.c_str());
    si.shi2_path = share;   //
    si.shi2_passwd = NULL;  // 不需要密码
    QString path = dir;
    // 获取最后一个反斜杠的位置
    qDebug() << "toNativeSeparators =" << QDir::toNativeSeparators(dir);
    int lastIndex = path.lastIndexOf('\\');
    // 提取最后一个反斜杠后的文件夹名称
    QString packageName = path.mid(lastIndex + 1);
    std::wstring wPackageName = packageName.toStdWString();
    LMSTR lPackageName = const_cast<LMSTR>(wPackageName.c_str());
    si.shi2_netname = lPackageName;
    // 输出结果
    qDebug() << "last folder name:" << packageName;
    // 添加共享
    NET_API_STATUS status = NetShareAdd(NULL, 2, (LPBYTE)&si, &parm_err);
    if (status == NERR_Success) {
        sharedDirList.append(dir);
        std::cout << "Success share add" << parm_err << std::endl;
    } else {
        std::cout << "Failed share add" << status << std::endl;
    }
    qDebug() << "dir:" << dir;
    qDebug() << "last folder name:" << packageName;
}

/*
 *  netname 使用的是，共享的“名称”，而不是文件系统的路径。
 *  共享名称  在创建共享时指定的名称，
 *  通常是共享目录的简单名称，而不应包含完整路径。
 *  删除的共享名称是已经创建的共享名
 */
void MainWindow::on_pushButtonDeleteShare_clicked()
{
    auto packageNames = netNameToPath.keys();
    for(auto pkg : packageNames) {
        std::wstring wPkg = pkg.toStdWString();
        LMSTR lPackageName = const_cast<LMSTR>(wPkg.c_str());
        NET_API_STATUS nStatus = NetShareDel(NULL, lPackageName, 0); // servername 为 NULL 表示本地计算机
        if (nStatus == NERR_Success) {
            qDebug() << "Success share del: " << nStatus;
        } else {
            qDebug() << "Failed share del: " << nStatus;
        }
    }

    if (packageNames.isEmpty()) {
        QString path = ui->lineEditDirShare->text();
        int lastIndex = path.lastIndexOf('\\');
        // 提取最后一个反斜杠后的文件夹名称
        QString packageName = path.mid(lastIndex + 1);
        auto wPkg = packageName.toStdWString();
        LMSTR lPackageName = const_cast<LMSTR>(wPkg.c_str());
        NET_API_STATUS nStatus = NetShareDel(NULL, lPackageName, 0); // servername 为 NULL 表示本地计算机
        if (nStatus == NERR_Success) {
            qDebug() << "Success share del: " << nStatus;
        } else {
            qDebug() << "Failed share del: " << nStatus;
        }
    }
}

#include <windows.h>
#include <lm.h>
#include <iostream>
void MainWindow::getNetPC()
{
    LPBYTE buffer = NULL;
    DWORD entriesRead = 0, totalEntries = 0;
    NET_API_STATUS status = NetServerEnum(NULL, 100, &buffer, MAX_PREFERRED_LENGTH,
                                          &entriesRead, &totalEntries, SV_TYPE_ALL, NULL, NULL);
    if (status == NERR_Success || status == ERROR_MORE_DATA) {
        SERVER_INFO_100* serverInfo = (SERVER_INFO_100*)buffer;
        for (DWORD i = 0; i < entriesRead; i++) {
            qDebug() << "Computer: " << serverInfo[i].sv100_name;
        }
    } else {
        qDebug() << "Error: " << status;
    }

    if (buffer) {
        NetApiBufferFree(buffer);
    }
}

// 主动获取
void queryShares(const std::wstring& computerName) {

    QDir networkDevice(QString::fromStdWString(computerName));
    qDebug() << networkDevice.exists();
    qDebug() << networkDevice.entryInfoList();
    LPBYTE buffer = NULL;
    DWORD entriesRead = 0, totalEntries = 0;
    LMSTR share = const_cast<LMSTR>(computerName.c_str());
    DWORD resumeHandle = 0;
    do {
        DWORD entriesRead = 0, totalEntries = 0;
        LPBYTE buffer = NULL;
        std::cout << "NetShareEnum" << std::endl;
        NET_API_STATUS status = NetShareEnum(share, 2, &buffer, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            // 处理数据
            std::cout << "entriesRead: " << entriesRead;
            SHARE_INFO_2* shareInfo = (SHARE_INFO_2*)buffer;
            for (DWORD i = 0; i < entriesRead; i++) {
                QString dev = QString::fromStdWString(shareInfo[i].shi2_netname);
                qDebug() << "share Name: " << dev;
                qDebug() << "share Path: " << networkDevice.absoluteFilePath(dev);
            }
        } else {
            qDebug() << "NetShareEnum failed with error: ";
            break;
        }

        if (buffer) {
            NetApiBufferFree(buffer);
        }

    } while (resumeHandle != 0);
}

void MainWindow::on_pushButtonNetPC_clicked()
{
    std::cout << "queryShares" << std::endl;
    /* C++ 中，为了表示一个反斜杠，需要用\\ */
    QString hostName = QHostInfo::localHostName();
    QString netHostName("\\\\" + hostName);
    qDebug() << "hostNameDir" << netHostName;
   // queryShares(L"\\\\Szmcs11175");
    queryShares(netHostName.toStdWString().data());
    // listNetworkDevice();
}


#include <windows.h>
#include <lm.h>
#include <iostream>
#include <QDebug>

void MainWindow::listNetworkDevice() {
    SERVER_INFO_101 *pBuf = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS status = NetServerEnum(
        NULL,                // 获取本地网络计算机
        101,                 // 获取计算机的信息等级
        (LPBYTE*)&pBuf,      // 服务器信息结构体
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        SV_TYPE_WORKSTATION | SV_TYPE_SERVER,  // 过滤工作站和服务器
        NULL,                // 指定的域（如果为空，查询所有）
        &dwResumeHandle      // 分页查询时的句柄
        );

    if (status == NERR_Success) {
        std::cout << "Found " << dwEntriesRead << " computers:\n";
        for (DWORD i = 0; i < dwEntriesRead; ++i) {
            qDebug() << "Computer: " << pBuf[i].sv101_name;
        }
    } else {
        qDebug() << "Failed to enumerate computers. Error: " << status;
    }

    if (pBuf != nullptr) {
        NetApiBufferFree(pBuf);
    }
}

#include <windows.h>
#include <lm.h>
#include <winnetwk.h>
#include <QDebug>
#include <QString>
#include <QDir>
#include <iostream>

#pragma comment(lib, "Mpr.lib")
void MainWindow::setFolder(const QString &remotePath, const QString &localDrive) {
    if (remotePath.isEmpty()) {
        qDebug() << "Remote path is empty.";
        return;
    }
    qDebug() << "remotePath. = " << remotePath;

    // 检查是否已指定驱动器号
    QString driveLetter = localDrive.isEmpty() ? findAvailableDriveLetter() : localDrive;

    if (driveLetter.isEmpty()) {
        qDebug() << "No available drive letter.";
        return;
    }
    std::string strdriveLetter = driveLetter.toStdString();
    // 配置 NETRESOURCE 结构体
    NETRESOURCEA nr;
    ZeroMemory(&nr, sizeof(NETRESOURCEA));
    nr.dwType = RESOURCETYPE_DISK; // 资源类型：磁盘
    nr.lpLocalName = driveLetter.toLatin1().data(); // 本地驱动器号
    nr.lpRemoteName = driveLetter.toLatin1().data(); // 远程共享路径
    nr.lpRemoteName = driveLetter.toLocal8Bit().data(); // 远程共享路径
    nr.lpProvider = NULL;

    // 映射驱动器
    DWORD result = WNetAddConnection2A(&nr, NULL, NULL, CONNECT_TEMPORARY);
    if (result == NO_ERROR) {
        qDebug() << "Drive mapped successfully:" << driveLetter;
    } else {
        qDebug() << "Failed to map drive. Error code:" << result;
    }
}

QString MainWindow::findAvailableDriveLetter() {
    // 从 Z: 开始尝试，找到第一个可用的驱动器号
    for (char drive = 'Z'; drive >= 'A'; --drive) {
        QString drivePath = QString("%1:").arg(drive);
        LPCSTR path = drivePath.toLatin1().data();
        UINT driveType = GetDriveTypeA (path);
        if (driveType == DRIVE_NO_ROOT_DIR) {
            return drivePath;
        }
    }
    return QString(); // 未找到可用驱动器号
}

#include <QJsonObject>
#include <QJsonDocument>
void MainWindow::on_checkBoxEnableBroad_clicked(bool checked)
{
    if(checked) {
        QString hostName = QHostInfo::localHostName();
        QDir hostNameDir("\\\\" + hostName);
        qDebug() << "hostNameDir" << hostNameDir.path();

        qDebug() << "Host name:" << hostName;
        qDebug() << "Shared dir:" << hostNameDir.entryInfoList();
        qDebug() << "Shared dir:" << hostNameDir.entryList();

        QJsonObject obj;
        obj.insert("devicename", hostNameDir.absolutePath());
        int size = udpSocket->writeDatagram(QJsonDocument(obj).toJson(QJsonDocument::Compact), QHostAddress("255.255.255.255"), cast_port);
        if (-1 == size) {
            qDebug() << "writeDatagram error";
        } else {
            qDebug() << "size " << size;
        }
    }
}

bool MainWindow::isLocalAddress(const QHostAddress &addr)
{
    foreach (const QHostAddress &address, QNetworkInterface::allAddresses()) {
        if (addr.isEqual(address)) {
            return true;
        }
    }
    return false;
}


void MainWindow::on_pushButtonBroadcastHost_clicked()
{
    udpBroadCast.sendHostInfo(sharedDirList);
}

