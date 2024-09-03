#include "caboutdialog.h"
#include "ui_caboutdialog.h"
#include <QFile>
#include <QDesktopServices>

CAboutDialog::CAboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CAboutDialog)
{
    ui->setupUi(this);

    // 加载Qss风格
    QFile qssFile("./qss/dlg.qss");
    if (!qssFile.open(QFile::ReadOnly | QFile::Text))
        qWarning("failed to load dlg.qss file.");

    setStyleSheet(qssFile.readAll());
    qssFile.close();

    ui->widget->setFixedSize(QSize(528/2, 497/2));
    ui->widget->setStyleSheet("border-image: url(:/bgpic/panda.png)");

    ui->textEdit->setFrameStyle(QFrame::NoFrame | QFrame::Sunken);
    ui->textEdit->insertPlainText("EPON Packet Analyzer\n\n");
    ui->textEdit->insertPlainText("说明：\n");
    ui->textEdit->insertPlainText("1) 支持传统的.pcap文件格式；\n");
    ui->textEdit->insertPlainText("2) 支持通过Titan捕获的EPON报文；\n");
    ui->textEdit->insertPlainText("3) 不支持.pcapng文件格式，需先使用Wireshark另存为.pcap格式；\n\n");

    ui->textEdit->insertPlainText("Version: 0.3\n");
    ui->textEdit->insertPlainText("1) 增加过滤器功能，过滤条件之间的关系为\"And\"。\n");
    ui->textEdit->insertPlainText("2) 增加MPCP Gate报文Overlap检查；\n");
    ui->textEdit->insertPlainText("3) 右下角报文内容窗口支持行号与缩略图显示；\n");
    ui->textEdit->insertPlainText("4) 修正bug；\n\n");

    ui->textEdit->insertPlainText("Version: 0.2\n");
    ui->textEdit->insertPlainText("1) 增加按列排序功能；\n\n");

    ui->textEdit->insertPlainText("Version: 0.1\nEPON 报文解析器基本功能就绪。\n");
    ui->textEdit->setReadOnly(true);

    QTextCursor cursor = ui->textEdit->textCursor();
    cursor.movePosition(QTextCursor::Start);
    QTextCharFormat fmt = cursor.blockCharFormat();
    fmt.setForeground(QColor(234, 204, 82));
    fmt.setFont(QFont("Microsoft YaHei UI", 14, QFont::Bold));
    //fmt.setFontItalic(true);
    cursor.select(QTextCursor::LineUnderCursor);

    cursor.setCharFormat(fmt);
    cursor.movePosition(QTextCursor::Start);

    ui->textEdit->setTextCursor(cursor);

    QString emailHtml = "<a href=\"mailto: gzlldx@163.com\"><font color=#eacc52>gzlldx@163.com</font></a>";
    ui->labelEMail->setText(emailHtml);
    connect(ui->labelEMail, SIGNAL(linkActivated(QString)), this, SLOT(sendEMail(QString)));

    ui->labelWeb->setOpenExternalLinks(true);
    //ui->labelWeb->setText("<a style='color: #eacc52; text-decoration: none;' href=\"https://github.com/gzlldx/EPON-Packet-Parser\">https://github.com/gzlldx/EPON-Packet-Parser</a>");
    ui->labelWeb->setText("<a style='color: #eacc52; text-decoration: none;' href=\"https://github.com/gzlldx/EPON-Packet-Parser\">https://github.com/gzlldx/EPON-Packet-Parser</a>");

    QObject::connect(ui->btnOK, &QPushButton::clicked, this, [=](bool checked) { accept(); });
}

CAboutDialog::~CAboutDialog()
{
    delete ui;
}

void CAboutDialog::on_buttonBox_accepted()
{
    close();
}

void CAboutDialog::sendEMail(const QString &text)
{
    // 打开对应url的网址
    //  mailto:user@foo.com?subject=Test&body=Just a test
    qDebug() << text;
    QDesktopServices::openUrl(QUrl(text));
}


