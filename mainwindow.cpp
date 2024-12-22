#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QUrl>
#include <QUdpSocket>
#include <QDateTime>
#include <QNetworkInterface>

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

#include <QUrl>
#include <QFileDialog>
void MainWindow::on_pushButtonSelect_clicked()
{
    QString path = QFileDialog::getExistingDirectory(nullptr, ui->lineEditDirShared->text());
    ui->lineEditDirShared->setText(path);
}

#include <windows.h>
#include <lm.h>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")
void MainWindow::on_pushButtonShared_clicked()
{
    SHARE_INFO_2 si;
    DWORD parm_err;

    // 设置共享信息
    si.shi2_netname = L"SharedFolder";
    si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    si.shi2_remark = L"My shared folder";
    si.shi2_permissions = 0; // 权限已被废弃，设置为 0
    si.shi2_max_uses = -1; // 不限制用户数
    si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    si.shi2_path = L"F:/Notebook";
    si.shi2_passwd = NULL;// 共享不需要密码

    SHARE_INFO_502 si;
    NET_API_STATUS status;

    // 添加共享
    NET_API_STATUS status = NetShareAdd(NULL, 2, (LPBYTE)&si, &parm_err);
    if (status == NERR_Success) {
        std::cout << "Success " << parm_err << std::endl;
    } else {
        std::cout << "Failed " << status << std::endl;
    }

    // 设置共享资源名称
    LPCWSTR shareName = si.shi2_netname;

    // 初始化 SHARE_INFO_502 结构体
    ZeroMemory(&si, sizeof(SHARE_INFO_502));
    si.shi502_netname = (LPWSTR)shareName;
    si.shi502_type = STYPE_DISKTREE;
    si.shi502_remark = L"Shared Folder with Read-Only Permissions";

    // 调用 NetShareSetInfo 来更新共享设置
    status = NetShareSetInfo(NULL, shareName, 502, (LPBYTE)&si, NULL);

    if (status == NERR_Success) {
        std::wcout << L"Shared folder permissions updated successfully!" << std::endl;
    } else {
        std::wcout << L"Failed to update shared folder permissions. Error: " << status << std::endl;
    }
}

