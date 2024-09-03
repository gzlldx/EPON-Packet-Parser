#include "cpacketparser.h"
#include <QFile>
#include <QtEndian>
#include <QDateTime>
#include <QTimeZone>
#include <QTextEdit>
#include <QMessageBox>

CPacketParser::CPacketParser(QObject *parent)
    : QObject{parent}
{

}

CPacketParser::CPacketParser(
    QTableView *tableView, QStandardItemModel *tableModel,
    QSortFilterProxyModel *tableProxyModel,
    QTreeView *treeView, QStandardItemModel *treeModel,
    CHexEditor *textEdit)
{
    if (tableView)
        m_tableView = tableView;

    if (tableModel)
        m_tableModel = tableModel;

    if (tableProxyModel)
        m_tableProxyModel = tableProxyModel;

    if (treeView)
        m_treeView = treeView;

    if (treeModel)
        m_treeModel = treeModel;

    if (textEdit)
        m_textEdit = textEdit;

    // 处理左侧TableView的行切换事件，同步在右上TreeView显示Packet Details
    connect(tableView->selectionModel(), SIGNAL(currentChanged(QModelIndex, QModelIndex )), this, SLOT(on_tableView_CurrentChanged(QModelIndex , QModelIndex)));

    // TODO:
    connect(tableModel, SIGNAL(rowsInserted(QModelIndex, int , int)), this, SLOT(on_tableRowsInserted(QModelIndex, int, int)));

    // 处理右上TreeView选中节点事件，同步在右下TextEdit选中节点对应的报文内容
    connect(treeView->selectionModel(), SIGNAL(currentChanged(QModelIndex, QModelIndex )), this, SLOT(on_treeView_CurrentChanged(QModelIndex , QModelIndex)));

    // TODO:
    connect(m_treeModel, SIGNAL(rowsInserted(QModelIndex, int, int)), this, SLOT(on_rowsInserted(QModelIndex, int, int)));
}

CPacketParser::~CPacketParser()
{
    if (m_fileData)
        free(m_fileData);
}

PPError_t CPacketParser::OpenFile(QString fileName, bool titanFlag)
{
    QFile file(fileName);

    if (!file.open(QIODevice::ReadOnly))
    {
        file.close();
        return Error;
    }

    // 文件数组不空先释放内存
    if (!m_fileData)
    {
        m_fileSize        = 0;
        m_firstPacketTime = 0;
        m_totalPackets    = 0;
        free(m_fileData);
    }

    m_fileSize = file.size();
    m_fileData = (quint8 *)malloc(m_fileSize);
    if (!m_fileData)
    {
        file.close();
        return Error;
    }

    // 二进制方式读文件
    QDataStream ds(&file);
    ds.readRawData((char *)m_fileData, m_fileSize);

    qDebug("file size: %llu", m_fileSize);

    file.close();

    // 对于Titan包类型，重构成为标准Cap格式
    if (titanFlag)
    {
        // pcak next generation 报文头，数据整体向左移动0x138字节模拟旧的报文格式
        if (m_fileData[0] == 0x0a && m_fileData[1] == 0x0d && m_fileData[2] == 0x0d && m_fileData[3] == 0x0a)
        {
#if 0
            memmove(m_fileData, m_fileData + 0x13c, m_fileSize - 0x13c);
            m_fileSize -= 0x13c;
#endif
            QMessageBox::information(nullptr, "EPON Packet Analyzer", "无法支持pcapng格式文件，请用Wireshark转换为以cap结尾的旧格式再尝试加载！", QMessageBox::Ok);
            free(m_fileData);
            return Error;
        }

        if (m_fileData[0] != 0xd4 && m_fileData[1] != 0xc3 && m_fileData[2] != 0xb2 && m_fileData[3] != 0xa1)
        {
            QMessageBox::information(nullptr, "EPON Packet Analyzer", "非标准pcap报文格式，无法解析。", QMessageBox::Ok);
            free(m_fileData);
            return Error;
        }

        PCapPacketHeader *pktHeader   = nullptr;
        PCapPacketHeader *dstPktHeader = nullptr;
        PCapFileHeader *fileHeader = (PCapFileHeader *)m_fileData;
        quint32 offset    = FILE_HEADER_LEN;
        quint32 dstOffset = FILE_HEADER_LEN;
        quint8 *mirrorData = (quint8 *)malloc(m_fileSize);
        quint32 mirrorSize = m_fileSize;
        if (!mirrorData)
            return OK;

        memcpy(mirrorData, m_fileData, m_fileSize);
        quint32 count = 0;
        while (offset < mirrorSize)
        {
            pktHeader = (PCapPacketHeader *)&mirrorData[offset];
            // qDebug("caplen: %08x, len:%08x", pktHeader->capLen, pktHeader->len);
            dstPktHeader = (PCapPacketHeader *)&m_fileData[dstOffset];

            dstPktHeader->gmtTime = pktHeader->gmtTime;
            dstPktHeader->usTime  = pktHeader->usTime;
            dstPktHeader->capLen  = pktHeader->capLen - 22;
            dstPktHeader->len     = pktHeader->len - 22;

            // copy preamble
            offset    += PACKET_HEADER_LEN + 18;
            dstOffset += PACKET_HEADER_LEN;
            memcpy(&m_fileData[dstOffset], &mirrorData[offset], PREAMBLE_LEN);

            // copy data payload
            offset += (PREAMBLE_LEN + 8);
            dstOffset += PREAMBLE_LEN;
            memcpy(&m_fileData[dstOffset], &mirrorData[offset], pktHeader->capLen - 26);

            offset += (pktHeader->capLen - 26 - PREAMBLE_LEN);
            dstOffset += (pktHeader->capLen - 26 - PREAMBLE_LEN);

            // titan包没有CRC32，为构造包添加固定CRC32
            *(quint32 *)&m_fileData[dstOffset] = 0xffffffff;
            dstOffset += 4;

            m_fileSize -= 22;
        }

        qDebug() << "new size after removing titan payload: " << m_fileSize;

        free(mirrorData);
    }

    return OK;
}

PPError_t CPacketParser::ParsingPacket()
{
    PCapPacketHeader *pktHeader = nullptr;
    quint16 *pEtherType = nullptr;
    quint16 etherType = 0;
    quint32 offset = 0;
    quint32 count = 0;
    quint32 rollingTimes = 0;
    quint32 lastPacketTime = 0;
    quint32 saOffset = 0;
    quint32 daOffset = 0;
    PacketInfo_T pktInfo;
    quint16 *pOpCode = nullptr;
    quint16 opCode = 0;

    if (!m_fileData)
        return Error;

    DumpFileHeader();

    if (m_fileData[0] != 0xd4 && m_fileData[1] != 0xc3 && m_fileData[2] != 0xb2 && m_fileData[3] != 0xa1)
    {
        QMessageBox::information(nullptr, "EPON Packet Analyzer", "非标准pcap报文格式，无法解析。", QMessageBox::Ok);
        free(m_fileData);
        return Error;
    }

    // 先清空Table
    m_tableModel->removeRows(0, m_tableModel->rowCount());

    // 跳过文件头
    offset = FILE_HEADER_LEN;

    // 解析报文
    while (offset < m_fileSize)
    {
        pktHeader = (PCapPacketHeader *)&m_fileData[offset];
        if (count == 0)
        {
            m_firstPacketTime = pktHeader->usTime;
            lastPacketTime    = pktHeader->usTime;
        }

        if (pktHeader->usTime < lastPacketTime)
        {
            rollingTimes++;
            qDebug() << "rolling at index: " << count + 1;
            qDebug() << "rolling times   : " << rollingTimes;
        }

        count++;

        QList<QStandardItem *> valueList;
        QString strMac;

        // Seq No, column #0
        QStandardItem *value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        value->setText(QString("%1").arg(count));
        valueList << value;

        // Arrival time, column#1
        value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        QString strTime;
        strTime.setNum((pktHeader->usTime + 1000000 * rollingTimes - m_firstPacketTime) / 1000000.0, 'f', 6);
        value->setText(strTime);
        valueList << value;

        // SA, column#2
        saOffset = offset + PACKET_HEADER_LEN + MAC_ADDR_LEN + PREAMBLE_LEN;
        value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
        strMac = QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", m_fileData[saOffset], m_fileData[saOffset + 1], m_fileData[saOffset + 2],
                     m_fileData[saOffset + 3], m_fileData[saOffset + 4], m_fileData[saOffset + 5]);
        value->setText(strMac);
        valueList << value;

        // DA, column#3
        daOffset = offset + PACKET_HEADER_LEN + PREAMBLE_LEN;
        value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
        strMac = QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", m_fileData[daOffset], m_fileData[daOffset + 1], m_fileData[daOffset + 2],
                     m_fileData[daOffset + 3], m_fileData[daOffset + 4], m_fileData[daOffset + 5]);
        value->setText(strMac);
        valueList << value;

        // EtherType, column#4
        value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        pEtherType = (quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + MAC_ADDR_LEN * 2 + PREAMBLE_LEN];
        etherType = qToBigEndian(*pEtherType);
        QString strEtherType;

        if (etherType == 0x8808)
            strEtherType = "MPCP";
        else if (etherType == 0x8809)
            strEtherType = "OAM";
        else if (etherType == 0x800)
            strEtherType = "IPv4";
        else if (etherType == 0x806)
            strEtherType = "ARP";
        else if (etherType == 0x86dd)
            strEtherType = "IPv6";
        else
            strEtherType = QString::asprintf("%#04x", etherType);
        value->setText(strEtherType);
        valueList << value;

        // Sub Type Protocol, column#5
        QString strSubProtocol("");
        if (etherType == 0x8808)
        {
            pOpCode = (quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN];
            opCode = qToBigEndian(*pOpCode);
            if (opCode == 0x2)
                strSubProtocol.append("GATE");
            else if (opCode == 0x3)
                strSubProtocol.append("REPORT");
            else if (opCode == 0x4)
                strSubProtocol.append("REG-REQ");
            else if (opCode == 0x05)
                strSubProtocol.append("REGISTER");
            else if (opCode == 0x06)
                strSubProtocol.append("REG-ACK");
            else
                strSubProtocol.append("UNKNOWN");
        }
        value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        value->setText(strSubProtocol);
        valueList << value;

        // Cap length, column#6
        value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        value->setText(QString("%1").arg(pktHeader->capLen));
        valueList << value;

        // Extra infomation, column#7
        QString strInfo("");
        if (etherType == 0x8808)
        {
            quint16 llid = qToBigEndian(*(quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + 3]);
            strInfo.append(QString("LLID(0x%1)").arg(llid, 4, 16, QChar('0')));

            if (opCode == 0x2)
            {
                quint8 gateFlag = m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6];
                quint16 grantLen = qToBigEndian(*(quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6 + 1 + 4]);
                strInfo.append(QString(", Grant-Len: %1(TQ)").arg(grantLen));
                if ((gateFlag >> 3) & 0x1)
                    strInfo.append(QString(", Discovery Gate."));
                else
                    strInfo.append(QString(", Normal Gate."));
            }
            else if (opCode == 0x3)
            {
                quint8 queueSets = m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6];
                quint8 bitmap = 0;
                quint8 validQueueNums = 0;
                quint16 totalValidQueues = 0;
                quint32 totalReportLen = 0;
                strInfo.append(", ");

                for (int i=0; i<queueSets; i++)
                {
                    bitmap = m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6 + 1 + (i * 1) + totalValidQueues * 2];
                    validQueueNums = 0;
                    for (int k=0; k<8; k++)
                    {
                        if ((bitmap >> k) & 0x1)
                            validQueueNums++;
                    }

                    strInfo.append(QString("QSet-%1: ").arg(i));

                    for (int j=0; j<validQueueNums; j++)
                    {
                        quint16 reportLen = qToBigEndian(*(quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6 + 1 + (i * 1 + 1) + totalValidQueues * 2 + j * 2]);

                        totalReportLen += reportLen;

                        if (j == validQueueNums - 1)
                        {
                            if (i == queueSets - 1)
                                strInfo.append(QString("%1(TQ).").arg(reportLen));
                            else
                                strInfo.append(QString("%1(TQ), ").arg(reportLen));
                        }
                        else
                            strInfo.append(QString("%1-").arg(reportLen));
                    }

                    totalValidQueues += validQueueNums;
                }

                if (totalReportLen == 0) // no report information, display LLID only.
                    strInfo = QString("LLID(0x%1)").arg(llid, 4, 16, QChar('0'));
            }
            else if (opCode == 0x4)
            {
                quint8 regFlag = m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6];
                if (regFlag == 0x1)
                    strInfo.append(QString(", Register Request."));
                else if (regFlag == 0x3)
                    strInfo.append(QString(", De-register Request."));
                else
                    strInfo.append(QString(", flag: 0x%1.").arg(regFlag, 2, 16, QChar('0')));
            }
            else if (opCode == 0x5)
            {
                quint16 assignedPort = qToBigEndian(*(quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6]);
                strInfo.append(QString(", Assigned-Port: 0x%1.").arg(assignedPort, 4, 16, QChar('0')));
            }
            else if (opCode == 0x6)
            {

            }
        }
        value = new QStandardItem;
        value->setEditable(false);
        value->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        value->setText(strInfo);
        valueList << value;

        m_tableModel->appendRow(valueList);
        //m_tableModel->insertRow(m_tableModel->rowCount(), valueList);

        // 保存包序号、包内容（含PackettHeader)索引开始位置以及时间翻转次数到用户私有数据
        pktInfo.seqNo = count;
        pktInfo.pos   = offset;
        pktInfo.rollingTimes = rollingTimes;
        pktInfo.lastUsTime   = lastPacketTime;

        QModelIndex index = m_tableModel->index(m_tableModel->rowCount() - 1, 0);
        QVariant var = QVariant::fromValue(pktInfo);
        m_tableModel->setData(index, var, Qt::UserRole);

        lastPacketTime = pktHeader->usTime;
        offset = offset + PACKET_HEADER_LEN + pktHeader->capLen;
    }

    qDebug() << "total counts: " << count;

    m_totalPackets = count;

    // 调整行高 - 无效
    // m_tableView->resizeColumnsToContents();
    // m_tableView->resizeRowsToContents();

    return OK;
}

void CPacketParser::DumpFileHeader()
{
    PCapFileHeader *fileHeader = (PCapFileHeader *)&m_fileData[0];

    qDebug() << "==== File Header ====";
    qDebug("magic    : %#08x", fileHeader->magic);
    qDebug("majorVer : %#04x", fileHeader->majorVer);
    qDebug("minorVer : %#04x", fileHeader->minorVer);
    qDebug("thisZone : %#08x", fileHeader->thisZone);
    qDebug("sigFigs  : %#08x", fileHeader->sigFigs);
    qDebug("snapLen  : %#08x", fileHeader->snapLen);
    qDebug("linkType : %#08x", fileHeader->linkType);
}

void CPacketParser::on_tableView_CurrentChanged(const QModelIndex &curr, const QModelIndex &prev)
{
    QModelIndex index;
    quint32 offset = 0;
    quint32 pktStartPos = 0;
    PCapPacketHeader *pktHeader = nullptr;
    quint16 etherType = 0;
    quint16 opCode = 0;
    FieldInfo_T fieldInfo;
    QVariant varFieldInfo;

    if (!curr.isValid())
        return;

    // 关键，先转换获取排序前数据源对应的索引
    QModelIndex srcIndex = m_tableProxyModel->mapToSource(curr);

    // packet info信息储存在[row, 0]，获得[row, 0]索引而后读取私有数据
    index = m_tableModel->index(srcIndex.row(), 0);
    //index = m_tableModel->index(curr.row(), 0);
    if (!index.isValid())
        return;

    QVariant var = m_tableModel->data(index, Qt::UserRole);
    if (var.canConvert<PacketInfo_T>())
    {
        //清除右上TreeView
        m_treeModel->removeRows(0, m_treeModel->rowCount());

        PacketInfo_T pktInfo = var.value<PacketInfo_T>();
        qDebug("seqNo(%d), rollingtimes(%d), pos(%d)\n", pktInfo.seqNo, pktInfo.rollingTimes, pktInfo.pos);

        offset      = pktInfo.pos;  // 在m_fileData中的偏移，包括packet header
        pktStartPos = pktInfo.pos + PACKET_HEADER_LEN;  // 实际数据包开始位置，不包括packet header


        pktHeader = (PCapPacketHeader *)&m_fileData[offset];
        qDebug() << "capLen:" <<pktHeader->capLen;
        qDebug() << "GMT   :" <<pktHeader->gmtTime;
        qDebug() << "usTime:" <<pktHeader->usTime;

        // dump data TextEdit
        dumpPacketData(&m_fileData[offset + PACKET_HEADER_LEN], pktHeader->capLen);

        // 获取不可见的根节点指针
        QStandardItem *rootNode = m_treeModel->invisibleRootItem();

        // Frame I 父节点
        QStandardItem *frameNode = new QStandardItem(QString("Frame I: %1 bytes on wire.").arg(pktHeader->capLen));
        fieldInfo.pos = 0;
        fieldInfo.len = pktHeader->capLen;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        frameNode->setData(varFieldInfo, Qt::UserRole);
        rootNode->appendRow(frameNode);

        // 转换GMT时间
        QDateTime dateTime;
        dateTime.setSecsSinceEpoch(pktHeader->gmtTime);

        // Frame I --> 绝对时间
        QStandardItem *gmtTime = new QStandardItem(dateTime.toString());
        frameNode->appendRow(gmtTime);

        // Frame I --> 微妙级到达时间，每1秒翻转
        QStandardItem *arrivalTime = new QStandardItem(QString("到达时间: %1us").arg(pktHeader->usTime));
        frameNode->appendRow(arrivalTime);

        // Frame I --> 前帧间隔
        QStandardItem *intervalFromPrevPacket = new QStandardItem(QString("前帧间隔: %1us").arg(pktHeader->usTime - pktInfo.lastUsTime));
        frameNode->appendRow(intervalFromPrevPacket);

        // Frame I --> 首帧间隔
        QStandardItem *intervalFromFirstPacket = new QStandardItem(QString("首帧间隔: %1us").arg(pktHeader->usTime + 1000000 * pktInfo.rollingTimes - m_firstPacketTime));
        frameNode->appendRow(intervalFromFirstPacket);

        // Preamble 节点
        offset += PACKET_HEADER_LEN;
        QStandardItem *preambleNode = new QStandardItem(QString("Preamble: 6 bytes."));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = PREAMBLE_LEN;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        preambleNode->setData(varFieldInfo, Qt::UserRole);
        rootNode->appendRow(preambleNode);

        QStandardItem *sldNode = new QStandardItem(QString("SLD : 0x%1").arg(m_fileData[offset], 0, 16));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = 1;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        sldNode->setData(varFieldInfo, Qt::UserRole);
        preambleNode->appendRow(sldNode);

        // 添加 Preamble.rsvd节点
        offset += 1;    // skip SLD
        QStandardItem *rsvdNode  = new QStandardItem(QString("RSVD: 0x%1").arg(qToBigEndian(*(quint16 *)&m_fileData[offset]), 0, 16));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = 2;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        rsvdNode->setData(varFieldInfo, Qt::UserRole);
        preambleNode->appendRow(rsvdNode);

        // 添加 Preamble.llid节点
        offset += 2;     // skip rsvd
        QStandardItem *llidNode  = new QStandardItem(QString("LLID: 0x%1").arg(qToBigEndian(*(quint16 *)&m_fileData[offset]), 0, 16));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = 2;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        llidNode->setData(varFieldInfo, Qt::UserRole);
        preambleNode->appendRow(llidNode);

        offset +=2;     // skip llid
        QStandardItem *crc8Node = new QStandardItem(QString("CRC8: 0x%1").arg(m_fileData[offset], 0, 16));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = 1;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        crc8Node->setData(varFieldInfo, Qt::UserRole);
        preambleNode->appendRow(crc8Node);

        // Ethernet 父节点
        offset +=1;     // skip crc8
        QStandardItem *etherNode = new QStandardItem(QString("Ethernet: 14 bytes."));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = pktHeader->capLen - PREAMBLE_LEN;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        etherNode->setData(varFieldInfo, Qt::UserRole);
        rootNode->appendRow(etherNode);

        // DA子节点
        QString strMAC = QString::asprintf("DMAC: %02x:%02x:%02x:%02x:%02x:%02x",
                        m_fileData[offset], m_fileData[offset + 1], m_fileData[offset + 2],
                        m_fileData[offset + 3], m_fileData[offset + 4], m_fileData[offset + 5]);
        QStandardItem *daNode = new QStandardItem(strMAC);
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = MAC_ADDR_LEN;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        daNode->setData(varFieldInfo, Qt::UserRole);
        etherNode->appendRow(daNode);

        // SA子节点
        offset += MAC_ADDR_LEN;
        strMAC = QString::asprintf("SMAC: %02x:%02x:%02x:%02x:%02x:%02x",
                       m_fileData[offset], m_fileData[offset + 1], m_fileData[offset + 2],
                       m_fileData[offset + 3], m_fileData[offset + 4], m_fileData[offset + 5]);
        QStandardItem *saNode = new QStandardItem(strMAC);
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = MAC_ADDR_LEN;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        saNode->setData(varFieldInfo, Qt::UserRole);
        etherNode->appendRow(saNode);

        // EtherType子节点
        offset += MAC_ADDR_LEN;
        etherType = qToBigEndian(*(quint16 *)&m_fileData[offset]);
        QStandardItem *ethTypeNode = new QStandardItem(QString("Type: 0x%1").arg(etherType, 4, 16, QChar('0')));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = 2;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        ethTypeNode->setData(varFieldInfo, Qt::UserRole);
        etherNode->appendRow(ethTypeNode);

        if (etherType != 0x8808)
        {
            QStandardItem *dataNode = new QStandardItem(QString("Payload: %1 byes.").arg(pktHeader->capLen - PACKET_HEADER_LEN - PREAMBLE_LEN - ETH_HEADER_LEN));
            rootNode->appendRow(dataNode);

            m_treeView->expandAll();
            return;
        }

        // 解析MPCP报文
        offset += 2;
        QStandardItem *mpcpNode = new QStandardItem(QString("MPCP: %1 bytes.").arg(pktHeader->capLen - ETH_HEADER_LEN - PREAMBLE_LEN - 4));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = pktHeader->capLen - (ETH_HEADER_LEN + PREAMBLE_LEN);
        varFieldInfo = QVariant::fromValue(fieldInfo);
        mpcpNode->setData(varFieldInfo, Qt::UserRole);
        rootNode->appendRow(mpcpNode);

        // OpCode字段
        opCode = qToBigEndian(*(quint16 *)&m_fileData[offset]);
        QStandardItem *opCodeNode = new QStandardItem(QString("Oper-Code: 0x%1").arg(opCode, 4, 16, QChar('0')));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = 2;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        opCodeNode->setData(varFieldInfo, Qt::UserRole);
        mpcpNode->appendRow(opCodeNode);

        // Timestamp字段
        offset += 2;
        QStandardItem *tsNode = new QStandardItem(QString("TimeStamp: %1(TQ)").arg(qToBigEndian(*(quint32 *)&m_fileData[offset + 2])));
        fieldInfo.pos = offset - pktStartPos;
        fieldInfo.len = 4;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        tsNode->setData(varFieldInfo, Qt::UserRole);
        mpcpNode->appendRow(tsNode);

        offset += 4;    // skip timestamp
        if (opCode == 2)
            mpcpGateHandler(mpcpNode, pktHeader, offset, pktStartPos);
        else if (opCode == 3)
            mpcpReportHandler(mpcpNode, pktHeader, offset, pktStartPos);

        m_treeView->expandAll();
    }
}

void CPacketParser::on_treeView_CurrentChanged(const QModelIndex &curr, const QModelIndex &prev)
{
    QVariant varFieldInfo = m_treeModel->data(curr, Qt::UserRole);
    if (varFieldInfo.canConvert<FieldInfo_T>())
    {
        FieldInfo_T fieldInfo = varFieldInfo.value<FieldInfo_T>();
        qDebug() << "fieldInfo: " << fieldInfo.pos << fieldInfo.len;

        QTextCursor cursor = m_textEdit->textCursor();
        cursor.setPosition(fieldInfo.pos * 3);
        cursor.setPosition(fieldInfo.pos * 3  + fieldInfo.len * 3 - 1, QTextCursor::KeepAnchor);
        m_textEdit->setTextCursor(cursor);
    }
}

void CPacketParser::on_rowsInserted(const QModelIndex &parent, int first, int last)
{

}

void CPacketParser::on_tableRowsInserted(const QModelIndex &parent, int first, int last)
{

}

void CPacketParser::mpcpGateHandler(QStandardItem *mpcpNode, PCapPacketHeader *pktHeader, quint32 fileOffset, quint32 pktStartPos)
{
    FieldInfo_T fieldInfo;
    QVariant varFieldInfo;

    // gate flag 节点
    QStandardItem *flagNode = new QStandardItem(QString("GateFlag : 0x%1").arg(m_fileData[fileOffset], 2, 16, QChar('0')));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 1;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    flagNode->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(flagNode);

    // grant number子节点，fieldInfo数据与gate flag父节点相同
    QStandardItem *grantNumberNode = new QStandardItem(QString("GrantNumber: %1").arg(m_fileData[fileOffset] & 0x1));
    grantNumberNode->setData(varFieldInfo, Qt::UserRole);
    flagNode->appendRow(grantNumberNode);

    // gate indicator子节点，fieldInfo数据与gate flag父节点相同
    quint8 gateInd = (m_fileData[fileOffset] >> 3) & 0x1;
    QString strGateInd = QString("Indicator  : %1").arg(gateInd);
    if (gateInd)
        strGateInd.append(" (Discovery Gate)");
    else
        strGateInd.append(" (Normal Gate)");
    QStandardItem *indicatorNode = new QStandardItem(strGateInd);
    grantNumberNode->setData(varFieldInfo, Qt::UserRole);
    flagNode->appendRow(indicatorNode);

    // force report子节点，fieldInfo数据与gate flag父节点相同
    QStandardItem *forceReportNode = new QStandardItem(QString("ForceReport: %1").arg((m_fileData[fileOffset] >> 4) & 0x1));
    forceReportNode->setData(varFieldInfo, Qt::UserRole);
    flagNode->appendRow(forceReportNode);

    // gate start time 节点
    fileOffset += 1;    // skip gate flag field
    QStandardItem *startTimeNode = new QStandardItem(QString("StartTime: %1(TQ)").arg(qToBigEndian(*(quint32 *)&m_fileData[fileOffset])));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 4;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    startTimeNode->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(startTimeNode);

    // gate length 节点
    fileOffset += 4;    // skip start time field
    QStandardItem *lengthNode = new QStandardItem(QString("Length   : %1(TQ)").arg(qToBigEndian(*(quint16 *)&m_fileData[fileOffset])));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 2;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    lengthNode->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(lengthNode);

    // padding 字段
    fileOffset += 2;    // skip gate length field
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = pktHeader->capLen - fieldInfo.pos - 4;  // minus CRC32 length
    varFieldInfo = QVariant::fromValue(fieldInfo);
    QString strPadding(fieldInfo.len * 2, QChar('0'));
    QStandardItem *paddingNode = new QStandardItem(QString("Padding  : ") + strPadding);
    paddingNode->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(paddingNode);

    // CRC32 字段
    fileOffset += fieldInfo.len;   // skip padding
    QStandardItem *crc32Node = new QStandardItem(QString("CRC32    : 0x%1").arg(qToBigEndian(*(quint32 *)&m_fileData[fileOffset]), 0, 16));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 4;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    crc32Node->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(crc32Node);
}

void CPacketParser::mpcpReportHandler(QStandardItem *reportNode, PCapPacketHeader *pktHeader, quint32 fileOffset, quint32 pktStartPos)
{
    FieldInfo_T fieldInfo;
    QVariant varFieldInfo;
    quint8 queueSetNums = 0;

    // report 节点
    queueSetNums = m_fileData[fileOffset];

    QStandardItem *qSetNumsNode = new QStandardItem(QString("QueueSetNums: %1").arg(queueSetNums));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 1;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    qSetNumsNode->setData(varFieldInfo, Qt::UserRole);
    reportNode->appendRow(qSetNumsNode);

    // queue-set group
    fileOffset += 1; // skip queue set number field

    for (int i=0; i<queueSetNums; i++)
    {
        QStandardItem *qSetNode = new QStandardItem(QString("QueueSet#%1  : 3 bytes.").arg(i));
        fieldInfo.pos = fileOffset - pktStartPos;
        fieldInfo.len = 3;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        qSetNode->setData(varFieldInfo, Qt::UserRole);
        reportNode->appendRow(qSetNode);

        // queue-set.reportBitmap field
        quint8 rptBitmap = m_fileData[fileOffset];
        QStandardItem *rptBmpNode = new QStandardItem(QString("ReportBitmap: 0x%1").arg(m_fileData[fileOffset], 2, 16, QChar('0')));
        fieldInfo.pos = fileOffset - pktStartPos;
        fieldInfo.len = 1;
        varFieldInfo = QVariant::fromValue(fieldInfo);
        rptBmpNode->setData(varFieldInfo, Qt::UserRole);
        qSetNode->appendRow(rptBmpNode);

        fileOffset += 1;    // skip report bitmap field
        for (int k=0; k<8; k++)
        {
            if ((rptBitmap >> k)  & 0x1)
            {
                // queue-set.queue_x_length field
                QStandardItem *queueLength = new QStandardItem(QString("Queue[%1]-Len: %2(TQ)").arg(k).arg(qToBigEndian(*(quint16 *)&m_fileData[fileOffset])));
                fieldInfo.pos = fileOffset - pktStartPos;
                fieldInfo.len = 2;
                varFieldInfo = QVariant::fromValue(fieldInfo);
                queueLength->setData(varFieldInfo, Qt::UserRole);
                qSetNode->appendRow(queueLength);

                fileOffset += 2;    // skip queue_k_length
            }
        }
    }
    // padding 字段
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = pktHeader->capLen - fieldInfo.pos - 4;  // minus CRC32 length
    varFieldInfo = QVariant::fromValue(fieldInfo);
    QString strPadding(fieldInfo.len * 2, QChar('0'));
    QStandardItem *paddingNode = new QStandardItem(QString("Padding  : ") + strPadding);
    paddingNode->setData(varFieldInfo, Qt::UserRole);
    reportNode->appendRow(paddingNode);

    // CRC32 字段
    fileOffset += fieldInfo.len;   // skip padding
    QStandardItem *crc32Node = new QStandardItem(QString("CRC32    : 0x%1").arg(qToBigEndian(*(quint32 *)&m_fileData[fileOffset]), 0, 16));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 4;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    crc32Node->setData(varFieldInfo, Qt::UserRole);
    reportNode->appendRow(crc32Node);

}

void CPacketParser::mpcpRegReqHandler(QStandardItem *mpcpNode, PCapPacketHeader *pktHeader, quint32 fileOffset, quint32 pktStartPos)
{
    FieldInfo_T fieldInfo;
    QVariant varFieldInfo;

    // flags节点
    quint8 flags = m_fileData[fileOffset];

    QStandardItem *flagsNode = new QStandardItem(QString("Flags: 0x%1").arg(flags, 2, 16, QChar('0')));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 1;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    flagsNode->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(flagsNode);

    // pending grant节点
    fileOffset += 1;    // skip flags field
    QStandardItem *pendingNode = new QStandardItem(QString("Pending-Grants: %1").arg(m_fileData[fileOffset]));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 1;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    pendingNode->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(pendingNode);

    // padding节点
    fileOffset += 1;
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = pktHeader->capLen - fieldInfo.pos - 4;  // minus CRC32 length
    varFieldInfo = QVariant::fromValue(fieldInfo);
    QString strPadding(fieldInfo.len * 2, QChar('0'));
    QStandardItem *paddingNode = new QStandardItem(QString("Padding  : ") + strPadding);
    paddingNode->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(paddingNode);

    // CRC32 字段
    fileOffset += fieldInfo.len;   // skip padding
    QStandardItem *crc32Node = new QStandardItem(QString("CRC32    : 0x%1").arg(qToBigEndian(*(quint32 *)&m_fileData[fileOffset]), 0, 16));
    fieldInfo.pos = fileOffset - pktStartPos;
    fieldInfo.len = 4;
    varFieldInfo = QVariant::fromValue(fieldInfo);
    crc32Node->setData(varFieldInfo, Qt::UserRole);
    mpcpNode->appendRow(crc32Node);
}

void CPacketParser::dumpPacketData(quint8 *data, quint32 len)
{
    QString strData;

    m_textEdit->clear();

    m_textEdit->setData(data, len);
#if 0
    for (int i=0; i<len; i++)
    {
        if ((i & 0xf) == 0xf)
        {
            if (i == len - 1)
                strData.append(QString("%1").arg(data[i], 2, 16, QChar('0')));
            else
                strData.append(QString("%1\n").arg(data[i], 2, 16, QChar('0')));
        }
        else
        {
            if (i == len - 1)
                strData.append(QString("%1").arg(data[i], 2, 16, QChar('0')));
            else
                strData.append(QString("%1 ").arg(data[i], 2, 16, QChar('0')));
        }
    }

    m_textEdit->appendPlainText(strData);
#endif
}

QStringList CPacketParser::gateCheck()
{
    PCapPacketHeader *pktHeader = nullptr;
    quint16 *pEtherType = nullptr;
    quint16 etherType = 0;
    quint32 offset = 0;
    quint32 count = 0;
    quint32 lastGateSeqNo = 0;
    quint32 lastGrantStartTime = 0;
    quint32 lastGrantLen = 0;
    quint16 *pOpCode = nullptr;
    quint16 opCode = 0;
    QStringList result;
    quint32 gateFrameCount = 0;
    quint32 gateOverrlapingCount = 0;

    if (!m_fileData)
        return QStringList();

    // 跳过文件头
    offset = FILE_HEADER_LEN;

    // 解析报文
    while (offset < m_fileSize)
    {
        pktHeader = (PCapPacketHeader *)&m_fileData[offset];
        count++;

        pEtherType = (quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + MAC_ADDR_LEN * 2 + PREAMBLE_LEN];
        etherType = qToBigEndian(*pEtherType);

        if (etherType == 0x8808)
        {
            pOpCode = (quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN];
            opCode = qToBigEndian(*pOpCode);

            // Gate Frame
            if (opCode == 0x2)
            {
                quint8  gateFlag = m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6];
                quint32 grantStartTime = qToBigEndian(*(quint32 *)&m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6 + 1]);
                quint16 grantLen = qToBigEndian(*(quint16 *)&m_fileData[offset + PACKET_HEADER_LEN + ETH_HEADER_LEN + PREAMBLE_LEN + 6 + 1 + 4]);
                //if ((gateFlag >> 3) & 0x1)
                int guardBand = 8;

                gateFrameCount++;

                // overlap
                if ((lastGrantStartTime + lastGrantLen + guardBand) > grantStartTime)
                {
                    gateOverrlapingCount++;
                    result << QString("Grant overlapped: SeqNo[%1](start: %2,len: %3) <-> SeqNo[%4](start: %5,len: %6)").
                              arg(count).arg(grantStartTime).arg(grantLen).
                              arg(lastGateSeqNo).arg(lastGrantStartTime).arg(lastGrantLen);
                }

                lastGateSeqNo = count;
                lastGrantLen  = grantLen;
                lastGrantStartTime = grantStartTime;
            }
        }

        // 保存包序号、包内容（含PackettHeader)索引开始位置以及时间翻转次数到用户私有数据
        offset = offset + PACKET_HEADER_LEN + pktHeader->capLen;
    }

    result << QString("===============================\n%1 gate frames were checked.").arg(gateFrameCount);
    if (result.count() == 1)
        result << "No overlapped windows in the file.";
    else
        result << QString("%1 grant windows overlapped.").arg(gateOverrlapingCount);

    qDebug() << "total counts: " << count;

    return result;
}
