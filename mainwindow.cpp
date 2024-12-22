#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QUrl>
#include <QUdpSocket>
#include <QDateTime>
#include <QNetworkInterface>

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <windows.h>
#include <lm.h>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")

#include <QUrl>
#include <QFileDialog>
void setNTFSReadWritePermissions(const QString& folderPath) {
    PACL pOldAcl = NULL, pNewAcl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // 获取文件夹的现有权限
    LPCSTR path = reinterpret_cast<LPCSTR>(folderPath.toStdWString().c_str());
    DWORD dwRes = GetNamedSecurityInfo(
        path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &pOldAcl, NULL, &pSD
        );
    if (dwRes != ERROR_SUCCESS) {
        std::wcerr << L"获取权限失败，错误代码：" << dwRes << std::endl;
        return;
    }

    // 创建对 "Everyone" 的访问控制列表（ACL），赋予完全控制权限
    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.ptstrName = "Everyone";

    // 创建新的ACL
    dwRes = SetEntriesInAcl(1, &ea, pOldAcl, &pNewAcl);
    if (dwRes != ERROR_SUCCESS) {
        std::wcerr << L"设置ACL失败，错误代码：" << dwRes << std::endl;
        return;
    }

    LPSTR path1 = folderPath.toLatin1().data(); // 转换为 LPSTR
    // 设置新的文件夹权限
    dwRes = SetNamedSecurityInfo(
        path1, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, pNewAcl, NULL
        );
    if (dwRes != ERROR_SUCCESS) {
        std::wcerr << L"设置权限失败，错误代码：" << dwRes << std::endl;
    } else {
        std::wcout << L"文件夹权限设置成功!" << std::endl;
    }

    // 清理
    if (pOldAcl) LocalFree(pOldAcl);
    if (pNewAcl) LocalFree(pNewAcl);
    if (pSD) LocalFree(pSD);
}


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

    // for (const QNetworkInterface &interface : interfaces) {
    //     // 检查接口是否激活并正在运行
    //     if (interface.flags().testFlag(QNetworkInterface::IsUp) &&
    //         interface.flags().testFlag(QNetworkInterface::IsRunning)) {

    //         // 遍历接口的地址列表
    //         QList<QNetworkAddressEntry> entries = interface.addressEntries();
    //         for (const QNetworkAddressEntry &entry : entries) {
    //             QHostAddress ip = entry.ip();
    //             // 只处理 IPv4 地址
    //             if (ip.protocol() == QAbstractSocket::IPv4Protocol) {
    //                 qDebug() << "Interface:" << interface.humanReadableName();
    //                 qDebug() << "IP Address:" << ip.toString();
    //             }
    //         }
    //     }
    // }

}

MainWindow::~MainWindow()
{
    delete ui;
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


void MainWindow::on_pushButtonSelect_clicked()
{
    QString path = QFileDialog::getExistingDirectory(nullptr, ui->lineEditDirShared->text());
    ui->lineEditDirShared->setText(path);
}

// net share SharedFolder /delete
void MainWindow::on_pushButtonShared_clicked()
{
    SHARE_INFO_502 si;
    DWORD parm_err;

    // 设置共享信息
    // si.shi2_netname = L"SharedFolder";
    // si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    // si.shi2_remark = L"My shared folder";
    // si.shi2_permissions = 0; // 权限已被废弃，设置为 0
    // si.shi2_max_uses = -1; // 不限制用户数
    // si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    // si.shi2_path = L"F:/Notebook";
    // si.shi2_passwd = NULL;// 共享不需要密码


    SHARE_INFO_2 shareInfo;

    // 设置共享名称
    shareInfo.shi2_netname = L"package"; // 共享名称
    shareInfo.shi2_type = STYPE_DISKTREE;       // 共享类型
    shareInfo.shi2_remark = L"package"; // 备注
    shareInfo.shi2_permissions = ACCESS_ALL;    // 设置权限，或根据需求设置
    shareInfo.shi2_max_uses = -1;               // 无限制
    shareInfo.shi2_current_uses = 0;            // 当前使用数
    shareInfo.shi2_path = L"D:\\package";  // 共享路径
    shareInfo.shi2_passwd = NULL;                // 密码，若无需则为 NULL

    // 添加共享
    NET_API_STATUS status = NetShareAdd(NULL, 2, (LPBYTE)&shareInfo, &parm_err);
    if (status == NERR_Success) {
        std::cout << "Success add " << std::endl;
    } else {
        std::cout << "Failed add " << std::endl;
    }

    // QDir::toNativeSeparators()
    setNTFSReadWritePermissions("D:\\package");
}


void MainWindow::on_pushButtonSharedCancel_clicked()
{
    NET_API_STATUS status = NetShareDel(NULL, L"package", 0);
    if (status == NERR_Success) {
        qDebug() << "Success cancel " ;
    } else {
        qDebug() << "Failed cancel " ;
    }
}
