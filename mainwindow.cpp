#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QToolButton>
#include <QFile>
#include <QFileDialog>
#include <QDebug>
#include <QScrollArea>
#include <QLabel>
#include <QCheckBox>
#include "caboutdialog.h"
#include <QFile>
#include <QRandomGenerator>
//#include "cWordwrapdelegate.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    setWindowIcon(QIcon(":/images/Applications.ico"));
    setWindowTitle(tr("EPON Packet Analyzer 0.3"));

    // 自定义工具栏
    QAction *actOpenFile = new QAction;
    actOpenFile->setText("打开文件");
    actOpenFile->setIcon(QIcon(":/images/Open.png"));
    QAction *actAbout = new QAction("关于");
    actAbout->setIcon(QIcon(":/images/About.png"));
    QAction *actCheckOverlap = new QAction("重叠检查");
    actCheckOverlap->setIcon(QIcon(":/images/Activity Monitor.png"));
    QAction *actFilter = new QAction("过滤器");
    actFilter->setIcon(QIcon(":/images/Panel Settings.png"));

    connect(actOpenFile, SIGNAL(triggered()), this, SLOT(on_actionOpen_triggered()));
    connect(actAbout, SIGNAL(triggered()), this, SLOT(on_actionAbout_triggered()));
    connect(actCheckOverlap, SIGNAL(triggered()), this, SLOT(on_actionCheckGateOverlap_triggered()));
    connect(actFilter, SIGNAL(triggered()), this, SLOT(on_actionFilter_triggered()));

    // 创建Open按钮
    QToolButton *btnOpenFile = new QToolButton;
    btnOpenFile->setDefaultAction(actOpenFile);
    btnOpenFile->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);

    // 创建过滤器按钮
    QToolButton *btnFilter = new QToolButton;
    btnFilter->setDefaultAction(actFilter);
    btnFilter->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);

    // 创建overlap check按钮
    QToolButton *btnCheckOverlap = new QToolButton;
    btnCheckOverlap->setDefaultAction(actCheckOverlap);
    btnCheckOverlap->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    // 创建About按钮
    QToolButton *btnAbout = new QToolButton;
    btnAbout->setDefaultAction(actAbout);
    btnAbout->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);

    // 添加按钮
    ui->toolBar->addWidget(btnOpenFile);
    ui->toolBar->addWidget(btnFilter);
    ui->toolBar->addWidget(btnCheckOverlap);
    ui->toolBar->addSeparator();
    ui->toolBar->addWidget(btnAbout);
    ui->toolBar->setIconSize(QSize(25, 25));

    m_checkBoxTitanCap = new QCheckBox;
    m_checkBoxTitanCap->setText("泰坦格式");
    m_checkBoxTitanCap->setToolTip("文件为Titan捕获类型选择此项");
    ui->toolBar->addSeparator();
    ui->toolBar->addWidget(m_checkBoxTitanCap);

    ui->actionResultWin->setCheckable(true);
    ui->actionResultWin->setChecked(false);
    ui->logTextEdit->setVisible(false);
    //QAction
    connect(ui->actionResultWin, &QAction::triggered, this, [=](bool checked) {
        ui->logTextEdit->setVisible(checked);
    });

    // 创建左侧TableView对应的model
    m_tableModel = new QStandardItemModel(this);

    m_tableProxyModel = new CMySortFilterProxyModel(this);
    m_tableProxyModel->setSourceModel(m_tableModel);
    ui->tableView->setModel(m_tableProxyModel);

    m_treeModel = new QStandardItemModel(this);
    ui->treeView->setModel(m_treeModel);

    // 右侧TreeView与TextEdit比例3:1
    ui->vertSplitter->setStretchFactor(0, 3);
    ui->vertSplitter->setStretchFactor(1, 1);

    // 左侧TableView与右侧显示比例2:1
    ui->horzSplitter->setStretchFactor(0, 2);
    ui->horzSplitter->setStretchFactor(1, 1);

    // 上部与下部TextEdit比例5:1
    ui->updownSplitter->setStretchFactor(0, 2);
    ui->updownSplitter->setStretchFactor(1, 1);

    ui->updownSplitter->setHandleWidth(3);
    ui->vertSplitter->setHandleWidth(3);
    ui->horzSplitter->setHandleWidth(3);


    // 加载QSS
#if 0
    QFile qssFile("../PktAnalyzer/qss/ElegantDark.qss");
    //QFile qssFile("../PktAnalyzer/qss/MacOS.qss");
    if (!qssFile.open(QIODevice::ReadOnly | QIODevice::Text))
        qWarning("failed to load qss file.");

    this->setStyleSheet(qssFile.readAll());
    qssFile.close();
#endif

    initTableView(ui->tableView);

    initTreeView(ui->treeView);

    //initTextEdit(ui->textEdit, true);
    initTextEdit(ui->logTextEdit, false);

    initDumpEdit(ui->textEdit, false);

    // 创建 Parser对象
    m_packetParser = new CPacketParser(ui->tableView, m_tableModel, m_tableProxyModel, ui->treeView, m_treeModel, ui->textEdit);

    m_statusLabel = new QLabel;
    m_statusLabel->setMinimumWidth(200);
    ui->statusbar->addWidget(m_statusLabel);

    QFile menuFile("./qss/menu.qss");
    if (!menuFile.open(QIODevice::ReadOnly | QIODevice::Text))
        qDebug() << menuFile.errorString();

    ui->menubar->setStyleSheet(menuFile.readAll());
    menuFile.close();

    QFile glbFile("./qss/global.qss");
    if (!glbFile.open(QIODevice::ReadOnly | QIODevice::Text))
        qDebug() << glbFile.errorString();

    setStyleSheet(glbFile.readAll());
    glbFile.close();

    m_statusLabel->setStyleSheet("QLabel {color: white;}");
}

MainWindow::~MainWindow()
{
    if (m_packetParser)
        delete m_packetParser;

    delete ui;
}

void MainWindow::initTableView(QTableView *tableView)
{
    QStringList fields;

    if (!tableView)
        return;

    tableView->setFrameShape(QFrame::NoFrame);
    tableView->setFont(QFont("Consolas", 9));

    fields << "序号" << "时间" << "源MAC" << "目的MAC" << "协议类型" << "子协议" << "长度" << "信息";
    m_tableModel->setColumnCount(fields.count());

    for (int i=0; i<fields.count(); i++)
    {
        QStandardItem *itemTitle = new QStandardItem(fields.at(i));
        m_tableModel->setHorizontalHeaderItem(i, itemTitle);
    }

    // 排序设置
    ui->tableView->setSortingEnabled(true);
    ui->tableView->horizontalHeader()->setSortIndicatorShown(true);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder); // 按Col-0序号列排序

    // 设置默认列宽
    tableView->setColumnWidth(0, 50);
    tableView->setColumnWidth(1, 80);
    tableView->setColumnWidth(2, 130);
    tableView->setColumnWidth(3, 130);
    tableView->setColumnWidth(4, 70);
    tableView->setColumnWidth(5, 70);
    tableView->setColumnWidth(6, 50);
    tableView->setColumnWidth(7, 200);

    // 最右侧信息栏使用代理
    //tableView->setItemDelegateForColumn(7, new CWordWrapDelegate());

    // 第0、1列宽固定
    tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    tableView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
    // 最右边列宽随窗口大小自动扩展
    //tableView->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    tableView->horizontalHeader()->setStretchLastSection(true);

    // 选择行为：整行选取
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    // 选择模式：单行选取
    tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    // 表格只读
    tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 开启表格交替颜色
    tableView->setAlternatingRowColors(true);
    // 表格Grid样式，Qt::DotLine，Qt::SolidLine etc.
    tableView->setGridStyle(Qt::NoPen);

    tableView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    // 单元格垂直对齐
    tableView->verticalHeader()->setDefaultAlignment(Qt::AlignVCenter);

    // 隐藏最左侧默认行标号
    //tableView->verticalHeader()->hide();
    tableView->verticalHeader()->setHidden(true);

    // 单元格高度自动分配
    // 若要固定高度，可使用参数QHeaderView::Fixed 和 tableView->setRowHeight(0, xxx)
    tableView->verticalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tableView->setWordWrap(true);

    QFile qssFile("./qss/tableview.qss");
    if (!qssFile.open(QFile::ReadOnly | QFile::Text))
        qDebug() << qssFile.errorString();

    tableView->setStyleSheet(qssFile.readAll());
    qssFile.close();
}

void MainWindow::initTreeView(QTreeView *treeView)
{
    //ui->treeView->setHeaderHidden(true);    // 隐藏header栏
    ui->treeView->setLayoutDirection(Qt::LeftToRight);

    ui->treeView->setEditTriggers(QAbstractItemView::NoEditTriggers); // 节点不可编辑

    // 单列TreeView显示横向滚动条
    ui->treeView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->treeView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    m_treeModel->setColumnCount(1);

    // 设置TreeView表头
    QStandardItem *item = new QStandardItem("   内容解析");
    item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_treeModel->setHorizontalHeaderItem(0, item);

    connect(ui->treeView, SIGNAL(expanded(QModelIndex)), this, SLOT(do_treeViewUpdateScrollArea(QModelIndex)));
    connect(ui->treeView, SIGNAL(collapsed(QModelIndex)), this, SLOT(do_treeViewUpdateScrollArea(QModelIndex)));

    QFile qssFile("./qss/treeview.qss");
    if (!qssFile.open(QIODevice::ReadOnly | QIODevice::Text))
        qDebug() << qssFile.errorString();

    ui->treeView->setStyleSheet(qssFile.readAll());
    qssFile.close();
}

void MainWindow::initTextEdit(QTextEdit *textEdit, bool readOnly)
{
    //textEdit->setTextColor(QColor(0xf0, 0xf0, 0xf0));
    QPalette pal = textEdit->palette();
    pal.setBrush(QPalette::Base, QBrush(QColor(0x50, 0x50, 0x50)));
    pal.setBrush(QPalette::Text, QBrush(QColor(0xf0, 0xf0, 0xf0)));
    textEdit->setPalette(pal);

    textEdit->viewport()->setCursor(QCursor(Qt::PointingHandCursor));

    textEdit->setFrameShape(QFrame::NoFrame);

    textEdit->setFont(QFont("Consolas", 10));
    textEdit->setReadOnly(readOnly);
    textEdit->setWordWrapMode(QTextOption::NoWrap);
}

void MainWindow::initDumpEdit(CHexEditor *hexEdit, bool readOnly)
{
    // 设置字体色
    setStyleSheet("CHexEditor "
                  "{"
                  "color: #e0e0e0; background-color: #505050;"
                  "selection-background-color: #0d7e9c;"
                  "selection-color: #d5ba9f;"
                  "}");

    //hexEdit->setFont(QFont("Consolas", 10));
    hexEdit->setWordWrapMode(QTextOption::NoWrap);
    hexEdit->setFrameShape(QFrame::NoFrame);
    hexEdit->setLineNumHighlightEnabled(false);
    hexEdit->updateAnsiCharSize();
    hexEdit->setReadOnly(true);
    hexEdit->setThumbnail(true);
    //hexEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

#if 0
    quint8 testArr[70] = {0};
    for (int i=0; i<sizeof(testArr); i++)
        testArr[i] = QRandomGenerator::global()->bounded(0, 255);

    textEdit->setData(&testArr[0], sizeof(testArr));
#endif
}

void MainWindow::on_actionAbout_triggered()
{
    CAboutDialog dlg;

    dlg.setWindowTitle(tr("关于本程序"));
    dlg.setFixedSize(dlg.size());
    dlg.setWindowIcon(QIcon(":/images/images/About.png"));
    dlg.exec();
}

void MainWindow::on_actionOpen_triggered()
{
    QString fileName;

    fileName = QFileDialog::getOpenFileName(this, tr("Open File"), ".", tr("Pcap Files (*.pcap)"));
    if (fileName.isEmpty())
        return;

    if (!m_packetParser)
        m_packetParser = new CPacketParser(ui->tableView, m_tableModel, m_tableProxyModel, ui->treeView, m_treeModel, ui->textEdit);

    bool titanFlag = m_checkBoxTitanCap->isChecked();
    if (m_packetParser->OpenFile(fileName, titanFlag) != CPacketParser::OK)
        return;

    m_packetParser->ParsingPacket();

    m_statusLabel->setText(QString("总报文数：%1").arg(m_packetParser->packetCount()));

    //ui->tableView->resizeColumnToContents(7);
}

void MainWindow::do_treeViewUpdateScrollArea(const QModelIndex &index)
{
    // 根据内容调整列宽度
    ui->treeView->resizeColumnToContents(index.column());
}

void MainWindow::on_actionExit_triggered()
{
    close();
}


void MainWindow::on_actionCheckGateOverlap_triggered()
{
    QStringList result = m_packetParser->gateCheck();

    ui->logTextEdit->setVisible(true);

    if (result.isEmpty())
    {
        ui->logTextEdit->append(QString("No overlapped grant window."));
        return;
    }

    foreach (const QString &line, result)
    {
        ui->logTextEdit->append(line);
    }
}


void MainWindow::on_actionFilter_triggered()
{
    //if (!m_filterDlg)
    CFilterDialog *m_filterDlg = new CFilterDialog(this);
    m_filterDlg->setProxyModel(m_tableProxyModel);
    m_filterDlg->setAttribute(Qt::WA_DeleteOnClose);

    int ret = m_filterDlg->exec();
    if (ret == QDialog::Accepted)
    {

    }
}

