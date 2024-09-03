#ifndef CFILTERDIALOG_H
#define CFILTERDIALOG_H

#include <QDialog>
#include <QMap>
#include "cmysortfilterproxymodel.h"
#include <QMouseEvent>
#include <QRegularExpressionValidator>

namespace Ui {
class CFilterDialog;
}

class CFilterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CFilterDialog(QWidget *parent = nullptr);
    ~CFilterDialog();

    void setProxyModel(CMySortFilterProxyModel *model) { m_proxyModel = model; }

    // 标题名<->列号映射表
    QMap<QString, int> m_columnMap = {
        {QString("序号"),  0},   {QString("时间"), 1},
        {QString("源MAC"), 2},   {QString("目的MAC"), 3},
        {QString("协议类型"), 4}, {QString("子协议"), 5},
        {QString("长度"),  6},   {QString("信息"), 7}};
private slots:
        void on_cbKey_currentIndexChanged(int index);


protected:
    void mousePressEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;

private slots:
    void on_btnAddFilter_clicked();

    void on_btnClearAll_clicked();

    void on_cbKey_activated(int index);

    void on_btnApply_clicked();

    void on_btnOK_clicked();

    void on_btnCancel_clicked();

private:
    Ui::CFilterDialog *ui;

    CMySortFilterProxyModel *m_proxyModel = nullptr;
    QPoint m_clickedPos;
    bool   m_clickTitleFlag = false;

    QRegularExpressionValidator *m_vld_uint  = nullptr;
    QRegularExpressionValidator *m_vld_float = nullptr;
    QRegularExpressionValidator *m_vld_str   = nullptr;
    QRegularExpressionValidator *m_vld_mac   = nullptr;
};

#endif // CFILTERDIALOG_H
