#include "chexeditor.h"
#include <QPainter>
#include <QTextBlock>
#include <QByteArray>
#include <QScrollBar>
#include <QMenu>
#include <QActionGroup>
#include <QFile>

CHexEditor::CHexEditor(QWidget *parent) : QPlainTextEdit(parent)
{
    QFont defaultFont = QFont("Consolas", 9);
    setFont(defaultFont);

    // 创建行号区对象
    m_lineNumberArea = new HexLineNumberArea(this);
    m_lineNumberArea->setFont(defaultFont);
    m_lineNumberArea->setCursor(Qt::ArrowCursor);

    // 创建缩略图对象
    m_thumbnailArea = new ThumbnailArea(this);
    m_thumbnailArea->setFont(defaultFont);
    m_thumbnailArea->setCursor(Qt::OpenHandCursor);

    // 创建ruler区域
    m_rulerArea = new RulerArea(this);
    m_rulerArea->setFont(defaultFont);
    m_rulerArea->setCursor(Qt::ArrowCursor);

    viewport()->setCursor(Qt::PointingHandCursor); // 更改文本区鼠标指针
    setCursorWidth(2);                             // 光标宽度

    updateLineNumberAreaWidth(0);                  // 初始化行号宽度
    document()->setDocumentMargin(0);              // 文档边距控制

    // 顶部ruler区纵坐标提示字符串 01 02 ... 0f
    for (int i=0; i<m_hexNumPerLine; i++)
        m_rulerStr.append(QString::asprintf("%02x ", i));

    setOverwriteMode(true);

    // 配置右键上下文菜单
    setContextMenuPolicy(Qt::CustomContextMenu);
    //connect(this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(on_customContextMenuRequested(QPoint)));
    connect(this, &CHexEditor::customContextMenuRequested, this, &CHexEditor::on_customContextMenuRequested);

    connect(this, &CHexEditor::blockCountChanged, this, &CHexEditor::updateLineNumberAreaWidth);
    connect(this, &CHexEditor::updateRequest,     this, &CHexEditor::updateLineNumberArea);
    connect(this, &CHexEditor::cursorPositionChanged, this, &CHexEditor::onCursorPosChanged);

    connect(this->horizontalScrollBar(), &QAbstractSlider::valueChanged, this, [=]()
            {
                contentOffsetX = contentOffset().x();
                m_rulerArea->update();
            });


    //connect(document(), &QTextDocument::contentsChange, this, &CHexEditor::on_docContentsChanged);
    connect(document(), &QTextDocument::contentsChanged, this, &CHexEditor::on_docContentsChanged);
}

CHexEditor::~CHexEditor()
{
}

void CHexEditor::onCursorPosChanged()
{
    highlightCurrentLine();

    if (isReadOnly())
        return;

    QTextCursor cursor = textCursor();
    int pos = cursor.position();

    // index 2, 5, 8, 11 自动往后跳一个字符，每行最后一个\n正好替代一个空格字符, 16 * 3
    if (((pos + 1) % 0x3) == 0x0)
    {
        cursor.setPosition(pos + 1);
        setTextCursor(cursor);
    }
}

char CHexEditor::ansiCharToHex(const char value)
{
    if (value >= 0x30 && value <= 0x39) // 0 - 9 数字
        return value - 0x30;
    else
        return value - 87;    // 小写 a - f (-0x61 + 10)
}

void CHexEditor::on_docContentsChanged()
{
    if (isReadOnly())
        return;

    QTextCursor cursor = textCursor();
    if (cursor.position() < 0)  // setPlainText时会触发本事件，pos = -1
        return;

    static bool filterFlag = false;
    if (!filterFlag)
    {
        filterFlag = true;
        return;
    }
    else
        filterFlag = false;

    int pos = cursor.position();
    qDebug() << "+++++++++++++++++";
    qDebug() << "position:" << pos;
    int realPos = ((pos - 1) % 3 == 0) ? pos - 1 : pos - 2;
    qDebug() << "real pos:" << realPos;
    if (realPos < 0)
    {
        qDebug() << "filter the content change(real pos < 0)";
        return;
    }

    // 打高亮标签
    if (m_hlModifiedByte)
    {
        int highBitsPos = realPos;
        if (realPos % 3)
            highBitsPos = realPos - 1;  // realPos在低位时左移一个字符，总是记录高位位置

        // 不存在则保存当前位置
        if (!m_modifiedBytesPos.contains(highBitsPos))
            m_modifiedBytesPos << highBitsPos;

        qDebug() << m_modifiedBytesPos;

        QList<QTextEdit::ExtraSelection> tags;
        tags = extraSelections();

        // tag 0 储存整行高亮选择，先保存再恢复
        QTextEdit::ExtraSelection hlCurrLineTag = tags.at(0);
        tags.clear();
        tags.append(hlCurrLineTag);

        QTextCursor cursor = textCursor();

        // 重新添加所有修改过字节的标记
        QTextEdit::ExtraSelection selHex;
        selHex.format.setBackground(QColor(56, 112, 83)); //(QColor(0x60, 0x60, 0x75))
        selHex.format.setForeground(QColor(Qt::yellow).lighter());
        for (int i=0; i<m_modifiedBytesPos.count(); i++)
        {
            // 总是选择整字节
            cursor.setPosition(m_modifiedBytesPos.at(i));
            cursor.setPosition(m_modifiedBytesPos.at(i) + 2, QTextCursor::KeepAnchor);
            selHex.cursor = cursor;
            cursor.clearSelection();

            tags.append(selHex);
        }

        setExtraSelections(tags);

        qDebug() << "tags count:" << tags.count();
    }

    // 所在行号
    int lineNum   = realPos / (m_hexNumPerLine * 3);
    int posInLine = realPos % (m_hexNumPerLine * 3);
    QString lineText;
    lineText = document()->findBlockByLineNumber(lineNum).text();
    // 组合两个ansi char为16进制数
    qint8 high4Bits = 0, low4Bits = 0;
    if (realPos % 3 == 0)
    {
        high4Bits = ansiCharToHex(lineText.at(posInLine).toLatin1());
        low4Bits  = ansiCharToHex(lineText.at(posInLine + 1).toLatin1());
    }
    else
    {
        high4Bits = ansiCharToHex(lineText.at(posInLine - 1).toLatin1());
        low4Bits  = ansiCharToHex(lineText.at(posInLine).toLatin1());
    }

    quint8 newValue = (high4Bits << 4) | low4Bits;
    // 每个16进制数占用ansi字符3个, XX_, 一行最后一个XX\n
    int offset = lineNum * m_hexNumPerLine + posInLine / 3;
    m_fileData[offset] = newValue;

    return;
}

void CHexEditor::on_customContextMenuRequested(const QPoint &pos)
{
    QMenu *popMenu = new QMenu(this);

    QAction *actRoMode = new QAction(tr("只读模式"));
    actRoMode->setObjectName(QString::fromLatin1("actionRoMode"));
    QAction *actRwMode = new QAction(tr("修订模式"));
    actRwMode->setObjectName(QString::fromLatin1("actionRwMode"));
    QAction *actCopy  = new QAction(tr("复制"));
    actCopy->setObjectName(QString::fromLatin1("actionCopy"));
    QAction *actSelectAll  = new QAction(QIcon(":/images/Selection.png"), tr("全部选择"));
    actSelectAll->setObjectName(QString::fromLatin1("actionSelectAll"));

    QActionGroup *modeGroup = new QActionGroup(popMenu);
    modeGroup->addAction(actRoMode);
    modeGroup->addAction(actRwMode);

    actRoMode->setCheckable(true);
    actRwMode->setCheckable(true);

    if (overwriteMode())
        actRwMode->setChecked(true);
    else
        actRoMode->setChecked(true);

    // 加入菜单
    popMenu->addAction(actRoMode);
    popMenu->addAction(actRwMode);
    popMenu->addSeparator();
    popMenu->addAction(actCopy);
    popMenu->addAction(actSelectAll);

    connect(actRoMode,    &QAction::triggered, this, &CHexEditor::on_actionFileModeTriggered);
    connect(actRwMode,    &QAction::triggered, this, &CHexEditor::on_actionFileModeTriggered);
    connect(actCopy,      &QAction::triggered, this, &QPlainTextEdit::copy);
    connect(actSelectAll, &QAction::triggered, this, &QPlainTextEdit::selectAll);

    popMenu->exec(cursor().pos());
    delete popMenu;
}

void CHexEditor::on_actionFileModeTriggered(bool checked)
{
    QAction *action =qobject_cast<QAction *>(sender());

    if (action->objectName() == "actionRoMode")
        setOverwriteMode(false);
    else if (action->objectName() == "actionRwMode")
        setOverwriteMode(true);
    else
        qDebug() << "invalid action:" << action;
}

// 重新计算行号区域宽度，当行数目变化时，blockCountChanged事件触发本函数计算。
void CHexEditor::updateLineNumberAreaWidth(int newBlockCount)
{
    // PlainEdit 默认视口Margin为0，0，0，0，表示滚动区边缘到左、顶、右、底的距离
    // 左侧设置为行号区域宽度，则左侧行号区等同于从视口滚动区剥离，
    // 主体文字将不会显示在左侧被剥离的区域。
    int rightMargin = 0;
    if (m_hasThumbnail)
    {
        // 随着向左resize窗口，contentsRect宽度变小，因此rightMargin也相应变小，右侧缩略图可显示内容变少
        rightMargin = thumbnailAreaWidth();
        //rightMargin = rightMargin ? rightMargin - 1 :  0;   // 修订一个像素
    }

    setViewportMargins(lineNumberAreaWidth(), m_rulerAreaPaddingTop, rightMargin - 1, 0);
    // 右侧视口margin改变后会导致textEdit横向滚动条无法出现或点击时消失，设置一下滚动条最大宽度
    //if (m_hasThumbnail)
        //viewport()->setMaximumWidth(lineRect.width() + rightMargin);
}

int CHexEditor::lineNumberAreaWidth()
{
    // 行号固定8个字符宽 + 左右填充宽度
    return m_lineAreaPaddingLeft +
           m_lineAreaPaddingRight +
           (fontMetrics().horizontalAdvance(QLatin1Char('9')) << 3);
}

int CHexEditor::thumbnailAreaWidth()
{
    // 每行显示输出 m_hexNumPerLine Hex数字, 每数字占用宽度m_hexNumPerLine * 3字符
    int vScrollBarWidth = verticalScrollBar()->isVisible() ? verticalScrollBar()->rect().width() : 0;
    QString strMaxLine(m_hexNumPerLine * 3, QChar('F'));
    QRect lineRect = fontMetrics().boundingRect(strMaxLine);

    int width = 0;
    // document margin 左右都有，因此减去 documentMargin() * 2
    width = contentsRect().width() - lineRect.width() - lineNumberAreaWidth() - vScrollBarWidth - document()->documentMargin() * 2;
    width = width < 0 ? 0 : width;

    return width;
}

// updateReqest信号触发本函数
// 文本卷动时，rect包含整个视口区域，
// 当文本垂直卷动时，dy参数携带视口卷动的像素数。
void CHexEditor::updateLineNumberArea(const QRect &rect, int dy)
{
    if (dy) // 垂直滚动时
    {
        m_lineNumberArea->scroll(0, dy);    // 行号区同步滚动dy像素
        if (m_hasThumbnail)
            m_thumbnailArea->scroll(0, dy); // 缩略图区同步滚动dy像素
    }
    else
    {
        m_lineNumberArea->update(0, rect.y(), m_lineNumberArea->width(), rect.height());
        if (m_hasThumbnail)
            m_thumbnailArea->update(0, rect.y(), m_thumbnailArea->width(), rect.height());
    }

    //if (rect.contains(viewport()->rect()))
        updateLineNumberAreaWidth(0);
}

void CHexEditor::highlightCurrentLine()
{
    QList<QTextEdit::ExtraSelection> tags;
    tags = extraSelections();

    if (!isReadOnly()) {
        QTextEdit::ExtraSelection selection;

        selection.format.setBackground(m_currLineHighlightColor);
        selection.format.setProperty(QTextFormat::FullWidthSelection, true);
        selection.cursor = textCursor();
        selection.cursor.clearSelection();

        if (tags.isEmpty())
            tags.append(selection);
        else
            tags.replace(0, selection); // 高亮标签始终放在第一个元素
    }

    setExtraSelections(tags);
}

void CHexEditor::paintEvent(QPaintEvent *event)
{
    QPlainTextEdit::paintEvent(event);

    if (!m_hasThumbnail)
        return;

    QPainter dc(viewport());

    // 开启反锯齿
    dc.setRenderHint(QPainter::Antialiasing, true);

#if 0
 // 右侧缩略图虚线位置y坐标
    int vertSplitLine = viewport()->rect().right();
    QPen verticalLinePen = QPen(QColor(Qt::gray));
    verticalLinePen.setStyle(Qt::DotLine);
    dc.setPen(verticalLinePen);
    // 绘制右侧提示线
    dc.drawLine(vertSplitLine, contentsRect().top(), vertSplitLine, contentsRect().bottom());
#endif
}

// PlainEdit大小变化时，同步更新行号区域大小
void CHexEditor::resizeEvent(QResizeEvent *e)
{
    QPlainTextEdit::resizeEvent(e);
    QRect cr = contentsRect();

    // 窗口大小改变时，也需要更新一下行号区域，尽量保持主内容显示完整，右侧缩略图随着窗口缩小可以部分显示或不显示
    updateLineNumberAreaWidth(0);

    // 设定行号区大小
    m_lineNumberArea->setGeometry(QRect(cr.left(), cr.top() + m_rulerAreaPaddingTop, lineNumberAreaWidth(), cr.height()));

    // 设定缩略图区大小
    int hzBarHeight = horizontalScrollBar()->isVisible() ? horizontalScrollBar()->height() : 0;
    // 检查是否有横向滚动条，需要对缩略图区域的高度减去横向滚动条高度
    m_thumbnailArea->setGeometry(
        QRect(cr.left() + lineNumberAreaWidth() + viewport()->width(),
              cr.top() + m_rulerAreaPaddingTop, thumbnailAreaWidth(), cr.height() - hzBarHeight));

    // 设定顶部ruler区大小
    m_rulerArea->setGeometry(cr.left(), cr.top(), cr.width(), m_rulerAreaPaddingTop);
}

void CHexEditor::keyPressEvent(QKeyEvent *event)
{
    if ((event->key() >= Qt::Key_Left) && (event->key() <= (Qt::Key_Up + 3)))
    {
        QTextCursor cursor = textCursor();
        int pos = cursor.position();

        switch (event->key())
        {
        case Qt::Key_Up:
        case Qt::Key_Down:
            return QPlainTextEdit::keyPressEvent(event);

            break;
        case Qt::Key_Left:
            if ((pos) % 3 == 0)
            {
                if (pos >= 2)
                {
                    cursor.setPosition(pos - 2);    // 向左跳过空格+1字符
                    setTextCursor(cursor);
                }
            }
            else
                return QPlainTextEdit::keyPressEvent(event);
            break;
        case Qt::Key_Right:
            if ((pos + 1) % 3 == 0)
            {
                cursor.setPosition(pos + 1);        // 跳过空格
                setTextCursor(cursor);
            }
            else
                return QPlainTextEdit::keyPressEvent(event);

            break;
        default:
            break;
        }
    }
    else if (event->modifiers() & Qt::ControlModifier)
    {
        // 仅允许 Ctrl+Z、Ctrl+C
        if (event->key() == Qt::Key_Z || event->key() == Qt::Key_C)
            QPlainTextEdit::keyPressEvent(event);
    }
    else
    {
        QString inputKey = event->text();
        if (inputKey.isEmpty())
            return;

        //qDebug() << inputKey;
        QChar firstKey = inputKey[0].toLower();

        if (firstKey.isDigit() || (firstKey >= 'a' && firstKey <= 'f'))
        {
            if (overwriteMode())
            {
                QTextCursor cursor = textCursor();
                // characterCount()函数至少包括了一个额外的x2029，因此减1
                if (cursor.position() >= document()->characterCount() - 1)
                    return;

                QPlainTextEdit::keyPressEvent(event);
            }
        }
        else
            event->ignore();
    }
}

void CHexEditor::hideEvent(QHideEvent *event)
{
    // 隐藏时释放QByteArray内存
#if 0
    if (m_dataSize)
    {
        m_fileData = QByteArray();
        m_dataSize = 0;
    }
#endif
    QPlainTextEdit::hideEvent(event);
}

void CHexEditor::lineNumberAreaMouseEvent(QMouseEvent *event)
{
    QWidget::mousePressEvent(event);
}

void CHexEditor::lineNumberAreaMouseWheelEvent(QWheelEvent *event)
{
    QPoint numDegrees = event->angleDelta() / 8;

    if (!numDegrees.isNull())
    {
        // scrollContentsBy(int dx, int dy)
        QPoint numSteps = numDegrees / 15;
        int dy = 0;
        if (numSteps.y() > 0)
            dy = -3;
        else
            dy = 3;

        // + (-3) 表示向下滚动3行
        // + 3表示向上滚动3行
        verticalScrollBar()->setValue(verticalScrollBar()->value() + dy);
        event->accept();
        return;
    }

    QWidget::wheelEvent(event);
}

void CHexEditor::lineNumberAreaPaintEvent(QPaintEvent *event)
{
    QPainter painter(m_lineNumberArea);
    painter.setRenderHint(QPainter::Antialiasing, true);

    // 绘制行号默认背景
    painter.fillRect(event->rect(), m_lineNumBgColor);
    painter.setPen(m_lineNumTextColor);

    QTextBlock block = firstVisibleBlock();
    int blockNumber = block.blockNumber();
    int top    = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
    int height = qRound(blockBoundingRect(block).height());
    int bottom = top + height;

    int currLineNum = textCursor().blockNumber();
    while (block.isValid() && top <= event->rect().bottom()) {
        if (block.isVisible() && bottom >= event->rect().top()) {
            // 当前行号背景高亮与否
            if (m_lineNumHighlightEnabled && blockNumber == currLineNum)
            {
                QRect highLightAreaRect(0, top, m_lineNumberArea->width(), fontMetrics().height() + 1);
                painter.fillRect(highLightAreaRect, m_lineNumHighlightBgColor);
            }

            // 当前行的行号字体加粗与否
            if (m_lineNumHighlightBold && blockNumber == currLineNum)
            {
                QFont font = painter.font();
                font.setBold(true);
                painter.setFont(font);
            }

            //painter.setPen(m_lineNumTextColor);
            // 右对齐方式绘制行号
            painter.drawText(0, top, m_lineNumberArea->width() - m_lineAreaPaddingRight, fontMetrics().height(),
                             Qt::AlignRight, QString("%1").arg(blockNumber << m_hexNumPowerPerLine, 8, 16, QChar('0')));

        }

        block = block.next();
        top = bottom;
        height = qRound(blockBoundingRect(block).height());
        bottom = top + height;
        ++blockNumber;
    }

    // 绘制行号区竖线
    int vertLineX = lineNumberAreaWidth() - 4;
    painter.drawLine(vertLineX, 0, vertLineX, contentsRect().height());
}

void CHexEditor::thumbnailAreaMouseWheelEvent(QWheelEvent *event)
{
    return lineNumberAreaMouseWheelEvent(event);
}

void CHexEditor::thumbnailAreaPaintEvent(QPaintEvent *event)
{
    if (!m_hasThumbnail)
        return;

    if (m_dataSize <= 0)
        return;

    char *fileData = m_fileData.data();

    QPainter painter(m_thumbnailArea);
    painter.setRenderHint(QPainter::Antialiasing, true);

    if (m_thumbnailSpliter)
    {
        // 缩略图左侧竖虚线位置y坐标
        QPen splitLinePen = QPen(QColor(Qt::gray));
        splitLinePen.setStyle(Qt::DotLine);
        painter.setPen(splitLinePen);
        // 绘制缩略图区左侧竖虚线提示线
        painter.drawLine(1, contentsRect().top(), 1, contentsRect().bottom());
    }

    // 绘制缩略图区默认背景
    //painter.fillRect(event->rect(), palette().brush(QPalette::Base).color());
    painter.setPen(m_thumbnailAreaTextColor);

    QTextBlock block = firstVisibleBlock();
    int blockNumber = block.blockNumber();
    int top    = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
    int height = qRound(blockBoundingRect(block).height());
    int bottom = top + height;

    while (block.isValid() && top <= event->rect().bottom()) {
        if (block.isVisible() && bottom >= event->rect().top()) {
            // 右对齐方式绘制char字符
            int loopFlag = m_hexNumPerLine;

            if ((blockNumber + 1) * m_hexNumPerLine > m_dataSize)
                loopFlag = m_dataSize % m_hexNumPerLine;

            QString strChar;
            for (int i=0; i<loopFlag; i++)
            {
                if ((blockNumber * m_hexNumPerLine + i) >= m_dataSize)
                    break;

                if ((quint8)fileData[blockNumber * m_hexNumPerLine + i] < 32 ||
                    ((quint8)fileData[blockNumber * m_hexNumPerLine + i] >= 127 && (quint8)fileData[blockNumber * m_hexNumPerLine + i] < 160))
                    strChar = QString(".");
                else
                    strChar = QString::asprintf("%c", fileData[blockNumber * m_hexNumPerLine + i]);

                QRectF textRect(m_thumbnaiAreaLeftPadding + m_ansiCharWidth * i, top, m_ansiCharWidth, m_ansiCharHeight);
                painter.drawText(textRect, Qt::AlignLeft, strChar);
                //painter.drawText(m_thumbnaiAreaLeftPadding + charWidth * i,
                //                 top, charWidth, charHeight, Qt::AlignLeft, strChar);
            }
        }

        block = block.next();
        top = bottom;
        height = qRound(blockBoundingRect(block).height());
        bottom = top + height;
        ++blockNumber;
    }
}

void CHexEditor::rulerAreaPaintEvent(QPaintEvent *event)
{
    QPainter painter(m_rulerArea);
    painter.setRenderHint(QPainter::Antialiasing, true);

    QPen horzLinePen = QPen(QColor(0xea, 0xb3, 0x08));  // QColor(Qt::red));
    horzLinePen.setStyle(Qt::SolidLine);
    painter.setPen(horzLinePen);

    int centerWidth = m_ansiCharWidth * (m_hexNumPerLine * 3) + 2 * document()->documentMargin();
    int x1 = lineNumberAreaWidth();
    int y1 = m_rulerAreaPaddingTop - 4;

    // 绘制默认背景
    // int rightAreaCharsWidth = m_ansiCharWidth * m_hexNumPerLine + m_thumbnaiAreaLeftPadding;
    //painter.fillRect(contentsRect().x(), 0, x1 + centerWidth + rightAreaCharsWidth, m_rulerAreaPaddingTop, m_lineNumBgColor);
    painter.fillRect(contentsRect().x(), 0, contentsRect().width(), m_rulerAreaPaddingTop, m_lineNumBgColor);

    // 绘制顶部水平分隔线
    //painter.drawLine(x1, y1, x1 + centerWidth + rightAreaCharsWidth , y1); // 线最右侧为缩略图的右边缘
    painter.drawLine(x1, y1, contentsRect().right() , y1); // 线最右侧为窗体边缘

    // 绘制顶部 01 02 03 .. 0f...
    painter.drawText(x1 + document()->documentMargin() + contentOffsetX, y1 - m_ansiCharHeight - 4, centerWidth, m_ansiCharHeight, Qt::AlignLeft, m_rulerStr);
    //painter.drawText(x1, y1 - 8, m_rulerStr);
}

void CHexEditor::setData(quint8 *data, quint32 len)
{
    if (!data || !len)
        return;

    m_fileData.resize(len);
    m_dataSize = len;

    char *fileData = m_fileData.data();
    memcpy(fileData, data, len);

    QString strData;
    for (int i=0; i<len; i++)
    {
        if ((i & (m_hexNumPerLine - 1)) == (m_hexNumPerLine - 1))
            strData += QString::asprintf("%02x\n", fileData[i] & 0xff);
        else
            strData += QString::asprintf("%02x ", fileData[i] & 0xff);
    }

    setPlainText(strData);

    moveCursor(QTextCursor::Start);
}

void CHexEditor::clearData()
{
    if (m_dataSize)
    {
        qDebug() <<"CHexEditor::clearData()";

        setPlainText("");    // 清除编辑器显示的文本

        // 清空旧标记
        if (!m_modifiedBytesPos.isEmpty())
        {
            m_modifiedBytesPos.clear();
            QList<QTextEdit::ExtraSelection> tags;
            setExtraSelections(tags);   // 清空标记

            highlightCurrentLine();     // 重新高亮当前行
        }

        m_fileData = QByteArray();  // 释放内存
        m_dataSize = 0;
    }
}

void CHexEditor::openFile(const QString &fileName)
{
    QFile file(fileName);

    if (!file.open(QFile::ReadOnly))
    {
        qDebug() << "CHexEditor::openFile(): failed to open file:" << fileName;
        return;
    }

    m_dataSize = file.size();
    m_fileData.resize(m_dataSize);  // 分配内存

    char *fileData = m_fileData.data();
    if (file.read(fileData, m_dataSize) != m_dataSize)
    {
        qDebug() << "CHexEditor::openFile(): length error on reading file:" << fileName;

        m_fileData = QByteArray(); // 释放内存
        m_dataSize = 0;

        file.close();
        return;
    }
    file.close();

    QString strData;
    for (int i=0; i<m_dataSize; i++)
    {
        if ((i & (m_hexNumPerLine - 1)) == (m_hexNumPerLine - 1))
            strData += QString::asprintf("%02x\n", fileData[i] & 0xff);
        else
            strData += QString::asprintf("%02x ", fileData[i] & 0xff);
    }

    setPlainText(strData);

    moveCursor(QTextCursor::Start);

    // 读取文件时清空旧标记
    if (!m_modifiedBytesPos.isEmpty())
    {
        m_modifiedBytesPos.clear();
        QList<QTextEdit::ExtraSelection> tags;
        setExtraSelections(tags);   // 清空标记

        highlightCurrentLine();     // 重新高亮当前行
    }
}

void CHexEditor::saveFile(const QString &fileName)
{
    QFile file(fileName);

    QFile::remove(fileName);

    if (!file.open(QIODevice::WriteOnly))
    {
        qDebug() << "failed to open file for writting:" << fileName;
        return;
    }

    qint64 wrBytes = file.write(m_fileData, m_dataSize);
    if (wrBytes != m_dataSize)
        qDebug("failed: only %lld of %lld bytes written", wrBytes, m_dataSize);

    // 修保存文件时需要清除所有修订标记
    if (!m_modifiedBytesPos.isEmpty())
    {
        m_modifiedBytesPos.clear(); // 删除记录的位置信息

        QList<QTextEdit::ExtraSelection> tags;
        setExtraSelections(tags);   // 清空标记

        highlightCurrentLine();     // 重新高亮当前行
    }

    file.close();
}
