#ifndef CMYSORTFILTERPROXYMODEL_H
#define CMYSORTFILTERPROXYMODEL_H

#include <QSortFilterProxyModel>
#include <QObject>

class CMySortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    explicit CMySortFilterProxyModel(QObject *parent = nullptr);
    ~CMySortFilterProxyModel() {};
    void setFilter(int column, QString oper, QString value);
    void clearFilter();

    enum HeaderTitle {
        seqNo = 0,
        time,
        srcMac,
        dstMac,
        proto,
        subProto,
        length,
        info,
        end = info
    };

protected:
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override;
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

private:
    // 以列为key的字典，值为具体条件
    QMap <int, QString> m_filterValue;
    // 以列为key的操作符字典，取值范围：> < >= <= == !=
    QMap <int, QString> m_filterOper;
};

#endif // CMYSORTFILTERPROXYMODEL_H
