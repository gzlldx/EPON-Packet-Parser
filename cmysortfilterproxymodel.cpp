#include "cmysortfilterproxymodel.h"
#include <QStandardItemModel>

CMySortFilterProxyModel::CMySortFilterProxyModel(QObject *parent)
    : QSortFilterProxyModel{parent}
{

}

#define TABLE_HEADER_SEQ_NO 0
#define TABLE_HEADER_TIME  1
#define TABLE_HEADER_LEN 6

bool CMySortFilterProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    if (!left.isValid() || !right.isValid())
        return false;

    // 从原始数据源中获取数据
    QVariant leftData  = sourceModel()->data(left);
    QVariant rightData = sourceModel()->data(right);

    // seq-no和长度列按整数排序
    if (left.column() == CMySortFilterProxyModel::seqNo || left.column() == CMySortFilterProxyModel::length)
    {
        if (leftData.canConvert<quint32>() && rightData.canConvert<quint32>())
        {
            quint32 left  = leftData.toUInt();
            quint32 right = rightData.toUInt();

            return left < right ? true : false;
        }
    }
    else if (left.column() == CMySortFilterProxyModel::time)
    {
        if (leftData.canConvert<double>() && rightData.canConvert<double>())
        {
            double left  = leftData.toDouble();
            double right = rightData.toDouble();

            return left < right ? true : false;
        }
        /*
        if (leftData.toString().contains(QRegularExpression("[\\x4e00-\\x9f5a]+")))
        {
            qDebug() << "有汉字" << leftData.toString();
        }
        */
    }

    return QSortFilterProxyModel::lessThan(left, right);
}

// 主窗口设置具体的条件
// 例如：0列 >= 100，1列 == 80，所有条件组合关系为 AND。
void CMySortFilterProxyModel::setFilter(int column, QString oper, QString value)
{
    m_filterOper[column]  = oper;   // 阈值
    m_filterValue[column] = value;  // 操作符
}

void CMySortFilterProxyModel::clearFilter()
{
    m_filterOper.clear();
    m_filterValue.clear();
}

bool CMySortFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    // 转换sourceModel
    QStandardItemModel *srcModel = dynamic_cast<QStandardItemModel *>(sourceModel());

    foreach (int column, m_filterValue.keys())
    {
        QStandardItem *item = srcModel->item(sourceRow, column);
        if (item)
        {
            // 序列号#0，长度#6为整数
            if (column == 0 || column == 6)
            {
                quint32 value  = 0;

                // 获取列对应的阈值
                value = m_filterValue[column].toUInt();

                // 根据列操作符判断
                if (m_filterOper[column] == ">")
                {
                    if (item->text().toUInt() <= value)
                        return false;
                }
                else if (m_filterOper[column] == "<")
                {
                    if (item->text().toUInt() >= value)
                        return false;
                }
                else if (m_filterOper[column] == "==")
                {
                    if (item->text().toUInt() != value)
                        return false;
                }
                else if (m_filterOper[column] == ">=")
                {
                    if (item->text().toUInt() < value)
                        return false;
                }
                else if (m_filterOper[column] == "<=")
                {
                    if (item->text().toUInt() > value)
                        return false;
                }
                else if (m_filterOper[column] == "!=")
                {
                    if (item->text().toUInt() == value)
                        return false;
                }
                else
                {
                    qDebug() << "exception: unknown oper: " << m_filterOper[column];
                }

            }
            else if (column == 1)
            {
                // 时间#1为实数
                double value = m_filterValue[column].toDouble();
                // 根据列操作符判断
                if (m_filterOper[column] == ">")
                {
                    if (item->text().toDouble() <= value)
                        return false;
                }
                else if (m_filterOper[column] == "<")
                {
                    if (item->text().toDouble() >= value)
                        return false;
                }
                else if (m_filterOper[column] == "==")
                {
                    if (item->text().toDouble() != value)
                        return false;
                }
                else if (m_filterOper[column] == ">=")
                {
                    if (item->text().toDouble() < value)
                        return false;
                }
                else if (m_filterOper[column] == "<=")
                {
                    if (item->text().toDouble() > value)
                        return false;
                }
                else if (m_filterOper[column] == "!=")
                {
                    if (item->text().toDouble() == value)
                        return false;
                }
                else
                {
                    qDebug() << "exception: unknown oper: " << m_filterOper[column];
                }
            }
            else if (column == 7)
            {
                // 信息#7 仅支持操作符"contain"
                if (m_filterOper[column] == "contains")
                {
                    QString value = m_filterValue[column];
                    if (!item->text().contains(value))
                        return false;
                }
                else
                {
                    qDebug() << "exception: unknown oper: " << m_filterOper[column];
                }
            }
            else
            {
                // SA、DA、协议类型、子类型仅支持 ==或者!=，其它操作符忽略。
                if (m_filterOper[column] == "==")
                {
                    if (item->text() != m_filterValue[column])
                        return false;
                }
                else if (m_filterOper[column] == "!=")
                {
                    if (item->text() == m_filterValue[column])
                        return false;
                }
                else
                {
                    qDebug() << "not support operator" << m_filterOper[column] << "for column:" << column;
                }
            }
        }
    }

    return true;
}
