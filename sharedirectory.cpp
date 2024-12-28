#include "sharedirectory.h"
#include <QDir>
#include <QTimer>
#include <QHostInfo>
#include <QNetworkInterface>
#include <windows.h>
#include <lm.h>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")

ShareDirectory::ShareDirectory(QObject *parent)
    : QObject{parent}
{
    findInfoTimer = new QTimer(this);
    connect(findInfoTimer, &QTimer::timeout, this, &ShareDirectory::getInfoList);
    findInfoTimer->start(500);
}

void ShareDirectory::setFolder(const QString &dir)
{
    if (dir.isEmpty()) {
        qDebug() << "dir is empty";
        return;
    }

    SHARE_INFO_2 si;
    DWORD parm_err;
    // 设置共享信息
    si.shi2_netname = L"package";
    si.shi2_type = STYPE_DISKTREE; // 磁盘共享
    si.shi2_remark = L"package";
    si.shi2_permissions = 0; // 权限已被废弃，设置为 0
    si.shi2_max_uses = -1; // 不限制用户数
    si.shi2_current_uses = 0;  // 当前连接的用户数，通常初始化为 0
    // QString dir("D:\\package");
    // dir = ui->lineEditDirShare->text();


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

    qDebug() << "dir:" << dir;
    qDebug() << "last folder name:" << packageName;
}

void ShareDirectory::getInfoList()
{
    QString hostName = QHostInfo::localHostName();
    QDir hostNameDir("\\\\" + hostName);
    QFileInfoList current = hostNameDir.entryInfoList();
    qDebug() << "Host name:" << hostName;
    if(sharedInfoList == current) {

    } else {
        qDebug() << "sharedInfoList:" << sharedInfoList;
        sharedInfoList = current;
        qDebug() << "new sharedInfoList:" << sharedInfoList;
    }

    QList<QHostAddress> addresses = QNetworkInterface::allAddresses();
    for (const QHostAddress &address : addresses) {
        if (!address.isLoopback()) {  // 排除回环地址
            //  qDebug() << "Host IP Address:" << address.toString();
        } else {
            // qDebug() << "Loop IP Address:" << address.toString();
        }
    }
}


