#include "cfilterdialog.h"
#include "ui_cfilterdialog.h"
#include "cmysortfilterproxymodel.h"
#include <QFile>

CFilterDialog::CFilterDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CFilterDialog)
{
    ui->setupUi(this);

    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setWindowOpacity(1);
    setAttribute(Qt::WA_TranslucentBackground);

    QStringList titles;
    titles << "序号" << "时间" << "源MAC" << "目的MAC" << "协议类型" << "子协议" << "长度" << "信息";
    ui->cbKey->addItems(titles);

    QStringList opers;
    opers << ">" << ">=" << "==" << "!=" << "<" << "<=";
    ui->cbOper->addItems(opers);

    // apply 按钮禁用
    ui->btnApply->setEnabled(false);

    m_vld_uint  = new QRegularExpressionValidator(QRegularExpression("[0-9]{1,}"), this);
    m_vld_float = new QRegularExpressionValidator(QRegularExpression("[0-9]{1,}.[0-9]{1,}"), this);
    m_vld_str   = new QRegularExpressionValidator(QRegularExpression("[\\w\\-\\(\\)]*"), this);
    m_vld_mac   = new QRegularExpressionValidator(QRegularExpression("([0-9a-hA-H]{1,2}:){5}[0-9a-hA-H]{1,2}"), this);

    ui->lineEditValue->setValidator(m_vld_uint);

    // 加载Qss风格
    QFile qssFile("./qss/dlg.qss");
    if (!qssFile.open(QFile::ReadOnly | QFile::Text))
        qWarning("failed to load dlg.qss file.");

    ui->baseWidget->setStyleSheet(qssFile.readAll());
    ui->cbKey->setStyleSheet("");     // QT 6.2.4有bug，不得不给comboBox再设定一次空值样式表才起作用
    ui->cbOper->setStyleSheet("");

    qssFile.close();
}

CFilterDialog::~CFilterDialog()
{
    delete ui;
}

void CFilterDialog::on_cbKey_currentIndexChanged(int index)
{
    ui->lineEditValue->clear();

    if (index == 0 || index == 6)
        ui->lineEditValue->setValidator(m_vld_uint);
    else if (index == 1)
        ui->lineEditValue->setValidator(m_vld_float);
    else if (index == 2 || index == 3)
        ui->lineEditValue->setValidator(m_vld_mac);
    else
        ui->lineEditValue->setValidator(m_vld_str);
}

void CFilterDialog::on_btnAddFilter_clicked()
{
    bool hitFlag = false;

    int colIndex = ui->cbKey->currentIndex();
    QString colText = ui->cbKey->itemText(colIndex);

    int operIndex = ui->cbOper->currentIndex();
    QString operText = ui->cbOper->itemText(operIndex);

    QString value = ui->lineEditValue->text();
    if (value.isEmpty())
        return;

    QString syntax = colText + " " + operText + " " + value;

    // 查找listWidget是否已经配置了某列条件
    for (int i=0; i<ui->lwAllFilters->count(); i++)
    {
        QString itemText = ui->lwAllFilters->item(i)->text();

        if (itemText.contains(QRegularExpression(colText)))
        {
            // 更新相应的listItem
            ui->lwAllFilters->item(i)->setText(syntax);
            hitFlag = true;
            break;
        }
    }

    // 未匹配则添加新的listItem
    if (!hitFlag)
        ui->lwAllFilters->addItem(syntax);

    ui->btnApply->setEnabled(true);
#if 0
    // 配置到ProxyModel
    qDebug() << "setFilter: " << m_columnMap[colText] << operText << value;
    m_proxyModel->setFilter(m_columnMap[colText], operText, value);

    // 触发过滤
    m_proxyModel->setFilterRegularExpression("");
#endif
}


void CFilterDialog::on_btnClearAll_clicked()
{
    ui->lwAllFilters->clear();
    ui->btnApply->setEnabled(true);
}


void CFilterDialog::on_cbKey_activated(int index)
{
    if (index == CMySortFilterProxyModel::info)
    {
        ui->cbOper->clear();
        ui->cbOper->addItem(QString("contains"));
    }
    else if (index == CMySortFilterProxyModel::srcMac || index == CMySortFilterProxyModel::dstMac ||
             index == CMySortFilterProxyModel::proto || index == CMySortFilterProxyModel::subProto)
    {
        ui->cbOper->clear();
        ui->cbOper->addItem(QString("=="));
        ui->cbOper->addItem(QString("!="));
    }
    else
    {
        ui->cbOper->clear();

        QStringList opers;
        opers << ">" << ">=" << "==" << "!=" << "<" << "<=";
        ui->cbOper->addItems(opers);
    }
}


void CFilterDialog::on_btnApply_clicked()
{
    if (ui->lwAllFilters->count() == 0)
    {
        m_proxyModel->clearFilter();
    }
    else
    {
        for (int i=0; i<ui->lwAllFilters->count(); i++)
        {
            QString lineText = ui->lwAllFilters->item(i)->text();

            QStringList paras = lineText.split(' ');
            qDebug() << paras;

            m_proxyModel->setFilter(m_columnMap[paras.at(0)], paras.at(1), paras.at(2));
        }
    }

    // 触发过滤
    m_proxyModel->setFilterRegularExpression("");
}

void CFilterDialog::on_btnOK_clicked()
{
    on_btnApply_clicked();
    accept();
}


void CFilterDialog::on_btnCancel_clicked()
{
    close();
}

void CFilterDialog::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton)
    {
        if (ui->labelTitleSettings->rect().contains(event->pos()))
        {
            m_clickedPos = event->pos();
            m_clickTitleFlag = true;
        }
    }

    return QDialog::mousePressEvent(event);
}

void CFilterDialog::mouseReleaseEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton)
        m_clickTitleFlag = false;

    return QDialog::mouseReleaseEvent(event);
}

void CFilterDialog::mouseMoveEvent(QMouseEvent *event)
{
    if (m_clickTitleFlag)
        move(pos() + event->pos() - m_clickedPos);

    return QDialog::mouseMoveEvent(event);
}

