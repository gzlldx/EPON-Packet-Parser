#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include <QTableView>
#include <QTreeView>
#include "cpacketparser.h"
#include <QLabel>
#include <QCheckBox>
#include <QSortFilterProxyModel>
#include "cmysortfilterproxymodel.h"
#include "chexeditor.h"
#include "cfilterdialog.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_actionOpen_triggered();
    void on_actionAbout_triggered();
    void on_actionExit_triggered();
    void do_treeViewUpdateScrollArea(const QModelIndex &index);

    void on_actionCheckGateOverlap_triggered();

    void on_actionFilter_triggered();

private:
    Ui::MainWindow *ui;
    CMySortFilterProxyModel *m_tableProxyModel = nullptr;
    QStandardItemModel *m_tableModel = nullptr;
    QStandardItemModel *m_treeModel = nullptr;
    CPacketParser *m_packetParser = nullptr;
    QLabel *m_statusLabel = nullptr;
    QCheckBox *m_checkBoxTitanCap = nullptr;

    //CFilterDialog *m_filterDlg = nullptr;

    void initTableView(QTableView *tableView);
    void initTreeView(QTreeView *treeView);
    void initTextEdit(QTextEdit *textEdit, bool readOnly);
    void initDumpEdit(CHexEditor *hexEdit, bool readOnly);
};
#endif // MAINWINDOW_H
