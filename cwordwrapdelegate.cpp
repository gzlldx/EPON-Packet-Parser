#include "cwordwrapdelegate.h"
#include <QPainter>

CWordWrapDelegate::CWordWrapDelegate(QObject *parent) : QStyledItemDelegate(parent)
{

}

CWordWrapDelegate::~CWordWrapDelegate()
{

}

void CWordWrapDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    //QString strData = index.data(Qt::DisplayRole).toString();
    QString strData = index.model()->data(index, Qt::DisplayRole).toString();

    painter->drawText(option.rect, Qt::TextWrapAnywhere | Qt::AlignVCenter, strData);

    //如果当前有焦点，就绘制一个焦点矩形，否则什么都不做
    QRect smallRect = option.rect - QMargins(0,1,0,1);
    painter->drawRect(smallRect);
}
