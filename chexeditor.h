#ifndef CHEXEDITOR_H
#define CHEXEDITOR_H

#include <QPlainTextEdit>
#include <QObject>
#include <QWidget>

QT_BEGIN_NAMESPACE
class QPaintEvent;
class QResizeEvent;
class QSize;
class QWidget;
class QMouseEvent;
QT_END_NAMESPACE

class HexLineNumberArea;
class ThumbnailArea;

class CHexEditor : public QPlainTextEdit
{
    Q_OBJECT
public:
    CHexEditor(QWidget *parent = nullptr);
    ~CHexEditor();

    int lineNumberAreaWidth();
    int thumbnailAreaWidth();
    // 处理行号区域鼠标点击事件
    void lineNumberAreaMouseEvent(QMouseEvent *event);
    // 行号区鼠标滚动
    void lineNumberAreaMouseWheelEvent(QWheelEvent *event);
    // 处理行号区重绘事件
    void lineNumberAreaPaintEvent(QPaintEvent *event);

    // 缩略图鼠标滚动事件
    void thumbnailAreaMouseWheelEvent(QWheelEvent *event);
    // 缩略图区重绘事件
    void thumbnailAreaPaintEvent(QPaintEvent *event);

    // 顶部ruler区域重绘事件
    void rulerAreaPaintEvent(QPaintEvent *event);

    // 缩略图设置
    void setThumbnail(bool enable) { m_hasThumbnail = enable; }

    // 行号高亮设置
    void setLineNumHighlightBold(bool flag)        { m_lineNumHighlightBold = flag; }
    void setLineNumHighlightEnabled(bool flag)     { m_lineNumHighlightEnabled = flag; }
    void setLineNumHightlightBgColor(const QColor &color) { m_lineNumHighlightBgColor = color; }

    // 行号颜色设置
    void setLineNumBgColor(const QColor &color)   { m_lineNumBgColor   = color; }
    void setLineNumTextColor(const QColor& color) { m_lineNumTextColor = color; }

    // 每行显示多少个16进制数
    void setHexNumPerLine(int number) {
        if (number != 16 && number != 32)
            return;

        m_hexNumPerLine = number;

        if (number == 16)
            m_hexNumPowerPerLine = 4;
        else
            m_hexNumPowerPerLine = 5;

        m_rulerStr.clear();
        for (int i=0; i<m_hexNumPerLine; i++)
            m_rulerStr.append(QString::asprintf("%02x ", i));
    }

    // 是否开启修改字节的高亮
    void setHlModifiedByteEnabled(bool flag) { m_hlModifiedByte = flag; }

    // 设置Hex文本数据
    void setData(quint8 *data, quint32 len);

    void clearData();

    // 打开文件
    void openFile(const QString &fileName);
    // 保存文件
    void saveFile(const QString &fileName);

    // 设置缩略图文本颜色
    void setThumbnailAreaTextColor(const QColor &color) { m_thumbnailAreaTextColor = color; }

    // 更改字体后，更新字符宽度
    void updateAnsiCharSize() {
        QFontMetricsF metrics(font());
        m_ansiCharWidth  = metrics.horizontalAdvance(QChar('F'));
        m_ansiCharHeight = qRound(metrics.height());
    }

protected:
    virtual void paintEvent(QPaintEvent *event) override;
    virtual void resizeEvent(QResizeEvent *event) override;
    virtual void keyPressEvent(QKeyEvent *event) override;
    virtual void hideEvent(QHideEvent *event) override;

private slots:
    void onCursorPosChanged();
    void on_docContentsChanged();
    void updateLineNumberAreaWidth(int newBlockCount);
    void highlightCurrentLine();
    void updateLineNumberArea(const QRect &rect, int dy);
    void on_customContextMenuRequested(const QPoint &pos);
    void on_actionFileModeTriggered(bool checked);

private:
    char ansiCharToHex(const char value);    // 转换ascii码0-9,a-f 到16进制数字

private:
    QWidget *m_lineNumberArea = nullptr;  // 行号区对象
    QWidget *m_thumbnailArea  = nullptr;  // 缩略图区对象
    QWidget *m_rulerArea      = nullptr;  // 顶部ruler区域

    QByteArray m_fileData;      // 文件字节数组
    qint64  m_dataSize = 0;     // 保存当前打开的文件数组长度

    int m_hexNumPerLine        = 16;  // 每行显示多少个16进制数
    int m_hexNumPowerPerLine   = 4 ;  // 2^n，用于移位操作

    bool m_hasThumbnail = true;        //是否显示右侧缩略图
    int m_thumbnaiAreaLeftPadding = 8; // 绘制缩略图时左填充
    QColor m_thumbnailAreaTextColor = QColor(0xc0, 0xc0, 0xc0); // 缩略图区文字颜色
    bool m_thumbnailSpliter = true;   // 是否显示缩略图左侧虚线分隔条

    int m_lineAreaPaddingLeft  = 2;   //行号文字左侧留5像素画标记 5
    int m_lineAreaPaddingRight = 9;   //行号文字右侧留9像素画标记
    int m_rulerAreaPaddingTop  = 25;  // 顶部标尺区域保留高度 30

    // 高亮行背景色
    QColor m_currLineHighlightColor = QColor(0x30, 0x50, 0x80).lighter();
    // 行号区背景色
    QColor m_lineNumBgColor = QColor(0x40, 0x40, 0x40); /* QColor(0x60, 0x50, 0x60)*/
    // 行号文本颜色
    QColor m_lineNumTextColor  = QColor(0xea, 0xb3, 0x08); //QColor(Qt::yellow).lighter(160);
    // 行号是否高亮
    bool m_lineNumHighlightEnabled = false;
    // 行号高亮颜色
    QColor m_lineNumHighlightBgColor = m_currLineHighlightColor;
    // 当前行行号是否加粗显示
    bool m_lineNumHighlightBold = false;
    // 单个字符宽度
    qreal m_ansiCharWidth = 0;
    // 单个字符高度
    qreal m_ansiCharHeight = 0; // 行高
    // 顶部标尺字符串
    QString m_rulerStr;
    // 修改内容高亮标志
    bool m_hlModifiedByte = true;
    // 记录修改过的字节pos
    QList<int> m_modifiedBytesPos;

    //
    qreal contentOffsetX = 0;
};

class HexLineNumberArea : public QWidget
{
public:
    HexLineNumberArea(CHexEditor *editor) : QWidget(editor), m_hexEditor(editor)
    {
    }

    QSize sizeHint() const override
    {
        return QSize(m_hexEditor->lineNumberAreaWidth(), 0);
    }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        m_hexEditor->lineNumberAreaPaintEvent(event);
    }

    void mousePressEvent(QMouseEvent *event) override
    {
        m_hexEditor->lineNumberAreaMouseEvent(event);
    }

    void wheelEvent(QWheelEvent *event) override
    {
        m_hexEditor->lineNumberAreaMouseWheelEvent(event);
    }

private:
    CHexEditor *m_hexEditor;
};

class ThumbnailArea : public QWidget
{
public:
    ThumbnailArea(CHexEditor *editor) : QWidget(editor), m_hexEditor(editor)
    {

    }

    QSize sizeHint() const override
    {
        return QSize(0, 0); //QSize(m_hexEditor->lineNumberAreaWidth(), 0);
    }
protected:
    void paintEvent(QPaintEvent *event) override
    {
        m_hexEditor->thumbnailAreaPaintEvent(event);
    }

    void wheelEvent(QWheelEvent *event) override
    {
        m_hexEditor->thumbnailAreaMouseWheelEvent(event);
    }
private:
    CHexEditor *m_hexEditor;
};

class RulerArea : public QWidget
{
public:
    RulerArea(CHexEditor *editor) : QWidget(editor), m_hexEditor(editor)
    {

    }

    QSize sizeHint() const override
    {
        return QSize(0, 0); //QSize(m_hexEditor->lineNumberAreaWidth(), 0);
    }
protected:
    void paintEvent(QPaintEvent *event) override
    {
        m_hexEditor->rulerAreaPaintEvent(event);
    }
private:
    CHexEditor *m_hexEditor;
};
#endif // CHEXEDITOR_H
