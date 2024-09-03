#ifndef CPACKETPARSER_H
#define CPACKETPARSER_H

#include <QObject>
#include <QWidget>
#include <QTableView>
#include <QTreeView>
#include <QTextEdit>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>
#include <QPlainTextEdit>
#include "chexeditor.h"

#pragma pack(push)
#pragma pack(1)
typedef struct {
    quint32 magic;
    quint16 majorVer;
    quint16 minorVer;
    quint32 thisZone;
    quint32 sigFigs;
    quint32 snapLen;
    quint32 linkType;
}PCapFileHeader;

typedef struct {
    quint32 gmtTime;    // 秒计时，从格林尼治时间时间到抓包时的秒数
    quint32 usTime;     // 数据包到达时微秒时间，10000000时翻转
    quint32 capLen;     // 捕获的数据包真实长度
    quint32 len;        // 数据包真实长度，若文件中保存的不是完整数据包，则此长度大于CapLen
}PCapPacketHeader;

typedef struct {
    quint8 DA[6];
    quint8 SA[6];
    quint16 etherType;
}PEtherHeader;

typedef struct {
    quint32 seqNo;
    quint32 pos;
    quint32 rollingTimes;
    quint32 lastUsTime;
}PacketInfo_T;

Q_DECLARE_METATYPE(PacketInfo_T)

typedef struct {
    quint32 pos;
    quint32 len;
}FieldInfo_T;

Q_DECLARE_METATYPE(FieldInfo_T)

#pragma pack(pop)

typedef qint32 PPError_t ;

class CPacketParser : public QObject
{
    Q_OBJECT
public:
    #define FILE_HEADER_LEN   24
    #define PACKET_HEADER_LEN 16
    #define ETH_HEADER_LEN    14
    #define MAC_ADDR_LEN      6
    #define PREAMBLE_LEN      6

    typedef enum {
        OK = 0,
        Error = 1,
    }PPError;

    explicit CPacketParser(QObject *parent = nullptr);
    explicit CPacketParser(QTableView *tableView, QStandardItemModel *tableModel,
                           QSortFilterProxyModel *tableProxyModel,
                           QTreeView *treeView, QStandardItemModel *treeModel,
                           CHexEditor *textEdit);
    ~CPacketParser();

    PPError_t OpenFile(QString fileName, bool titanFlag);
    PPError_t ParsingPacket();
    void DumpFileHeader();
    void dumpPacketData(quint8 *data, quint32 len); // 右下角TextEdit显示报文内容

    QStringList gateCheck();
    quint32 packetCount() { return m_totalPackets; }
signals:

private slots:
    void on_tableView_CurrentChanged(const QModelIndex &curr, const QModelIndex &prev);
    void on_treeView_CurrentChanged(const QModelIndex &curr, const QModelIndex &prev);
    void on_rowsInserted(const QModelIndex &parent, int first, int last);
    void on_tableRowsInserted(const QModelIndex &parent, int first, int last);
    void mpcpGateHandler(QStandardItem *mpcpNode, PCapPacketHeader *pktHeader, quint32 fileOffset, quint32 pktStartPos);
    void mpcpReportHandler(QStandardItem *reportNode, PCapPacketHeader *pktHeader, quint32 fileOffset, quint32 pktStartPos);
    void mpcpRegReqHandler(QStandardItem *mpcpNode, PCapPacketHeader *pktHeader, quint32 fileOffset, quint32 pktStartPos);
private:
    QStandardItemModel *m_tableModel = nullptr;
    QSortFilterProxyModel *m_tableProxyModel = nullptr;
    QStandardItemModel *m_treeModel = nullptr;
    QTableView *m_tableView = nullptr;
    QTreeView *m_treeView   = nullptr;
    CHexEditor *m_textEdit   = nullptr;
    quint8  *m_fileData = nullptr;
    quint64 m_fileSize  = 0;
    quint32 m_firstPacketTime = 0;  // 记录首包到达时微秒值
    quint32 m_totalPackets = 0;
};

#endif // CPACKETPARSER_H
