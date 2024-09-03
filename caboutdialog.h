#ifndef CABOUTDIALOG_H
#define CABOUTDIALOG_H

#include <QDialog>

namespace Ui {
class CAboutDialog;
}

class CAboutDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CAboutDialog(QWidget *parent = nullptr);
    ~CAboutDialog();

private slots:
    void on_buttonBox_accepted();
    void sendEMail(const QString &text);

private:
    Ui::CAboutDialog *ui;
};

#endif // CABOUTDIALOG_H
