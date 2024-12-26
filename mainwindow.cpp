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
#include <QFileDialog>
#define CMD_SEND_DISP QString("[%1]# SEND ASCII TO %2:%3")
#define CMD_RECV_DISP QString("[%1]# RECV ASCII FROM %2:%3")
/*
 *  当前工具: 从服务器上获取支持的刷机包信息，本地如果没有，从接收到的广播信息中，
 *      检测局域网内其它工具的共享目录有没有需要的
 *
 */
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    socket = new QUdpSocket(this);
    // 绑定到端口502，接收来自该端口的数据包
    socket->bind(502, QUdpSocket::ShareAddress);  // 使用ShareAddress选项来允许其他应用程序共享该端口
    connect(socket, &QUdpSocket::readyRead, this, [=](){
        while(socket->hasPendingDatagrams())
        {
            QByteArray data;
            data.resize(socket->pendingDatagramSize());
            QHostAddress host;
            quint16 port;
            socket->readDatagram(data.data(), data.size(), &host, &port);
            QString time = QDateTime::currentDateTime().toString("yyyy-mm-dd hh:mm:ss.zzz");
            QByteArray text = CMD_RECV_DISP.arg(time).arg(QHostAddress(host.toIPv4Address()).toString()).arg(port).toLatin1();
            ui->textEditLog->append(text);
            qDebug() << "Host:" << host;  // 输出 "192.168.0.10"
            qDebug() << "Port:" << port;  // 输出 502
        }
    });
    QUrl url = QUrl::fromUserInput("192.168.72.1:502");
    qDebug() << "Host:" << url.host();  // 输出 "192.168.0.10"
    qDebug() << "Port:" << url.port();  // 输出 502

    // 获取所有网络接口
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    for (const QNetworkInterface &interface : interfaces) {
        // 检查接口是否激活并正在运行
        if (interface.flags().testFlag(QNetworkInterface::IsUp) &&
            interface.flags().testFlag(QNetworkInterface::IsRunning)) {

            // 遍历接口的地址列表
            QList<QNetworkAddressEntry> entries = interface.addressEntries();
            for (const QNetworkAddressEntry &entry : entries) {
                QHostAddress ip = entry.ip();
                // 只处理 IPv4 地址
                if (ip.protocol() == QAbstractSocket::IPv4Protocol) {
                    qDebug() << "Interface:" << interface.humanReadableName();
                    qDebug() << "IP Address:" << ip.toString();
                }
            }
        }
    }

    getCurrentDevice();
}

MainWindow::~MainWindow()
{
    delete ui;
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
    QString broadcast("255.255.255.255");
    int port(502);
    QString time = QDateTime::currentDateTime().toString("yyyy-mm-dd hh:mm:ss.zzz");
    QByteArray timeMsg = CMD_SEND_DISP.arg(time).arg(broadcast).arg(port).toLatin1();
    int size = socket->writeDatagram(ui->textEditSendMessage->toPlainText().toLatin1(), QHostAddress(broadcast), port);
    if (-1 == size) {
        qDebug() << "writeDatagram error";
    } else {
        qDebug() << "size " << size;
        ui->textEditLog->append(timeMsg + "\n" + ui->textEditSendMessage->toPlainText());
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
    DWORD dwRes = GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                       NULL, NULL, &oldAcl, NULL, &sd);

    if (dwRes != ERROR_SUCCESS) {
        qDebug() << "dwRes code：" << dwRes;
    }

    // 创建对 "Everyone" 的访问控制列表（ACL），赋予权限  完全控制GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_READ;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.ptstrName = "Everyone";

    // 创建新的ACL
    dwRes = SetEntriesInAcl(1, &ea, oldAcl, &newAcl);
    if (dwRes != ERROR_SUCCESS) {
        qDebug() << "set ACL failed, code：" << dwRes;
        return;
    }

    LPSTR path1 = folderPath.toLatin1().data(); // 转换为 LPSTR
    // 设置新的文件夹权限
    dwRes = SetNamedSecurityInfo(path1, SE_FILE_OBJECT,
                                 DACL_SECURITY_INFORMATION, NULL, NULL, newAcl, NULL);
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

/**
 * net share 共享名称=文件夹路径 /grant:Everyone,full
 * 使用 net share 命令共享文件夹
 *
 */

#include <windows.h>
#include <lm.h>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")

void MainWindow::on_pushButtonShare_clicked()
{
    SHARE_INFO_2 si;
    DWORD parm_err;
    // 设置共享信息
    si.shi2_netname = L"package";
    si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    si.shi2_remark = L"package";
    si.shi2_permissions = 0; // 权限已被废弃，设置为 0
    si.shi2_max_uses = -1; // 不限制用户数
    si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    QString dir("D:\\package");
    dir = ui->lineEditDirShare->text();
    // 将 QString 转换为 std::wstring
    std::wstring wShareName = dir.toStdWString();
    // 使用 c_str() 获取指向内部数据的指针
    LMSTR share = const_cast<LMSTR>(wShareName.c_str());
    si.shi2_path = share;   //  L"D:\\package";
    si.shi2_passwd = NULL;  // 共享不需要密码
    QString path = dir;
    // 获取最后一个反斜杠的位置
    qDebug() << "toNativeSeparators =" << QDir::toNativeSeparators(dir);
    int lastIndex = path.lastIndexOf('\\');
    // 提取最后一个反斜杠后的文件夹名称
    QString packageName = path.mid(lastIndex + 1);
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
    netNameToPath[packageName] = dir;
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
    queryShares(L"\\\\Szmcs11175");
}
