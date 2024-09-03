#ifndef CWORDWRAPDELEGATE_H
#define CWORDWRAPDELEGATE_H

#include <QStyledItemDelegate>
#include <QObject>
#include <QWidget>

class CWordWrapDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit CWordWrapDelegate(QObject *parent = nullptr);
    ~CWordWrapDelegate();

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
protected:

};

#endif // CWORDWRAPDELEGATE_H
