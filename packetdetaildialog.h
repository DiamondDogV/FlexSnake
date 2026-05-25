#ifndef PACKETDETAILDIALOG_H
#define PACKETDETAILDIALOG_H

#include <QDialog>
#include <QTreeWidget>
#include <QTextEdit>
#include <QPushButton>
#include "packetsniffer.h"

class PacketDetailDialog : public QDialog {
    Q_OBJECT

public:
    explicit PacketDetailDialog(const PacketData &data, QWidget *parent = nullptr);
    ~PacketDetailDialog();

private slots:
    void onDownloadClicked();

private:
    PacketData m_packetData;

    QTreeWidget *m_treeWidget;
    QTextEdit *m_hexEdit;
    QPushButton *m_btnDownload;

    void setupUiElements();
    void fillProtocolTree();
    void fillHexDump();

    static int file_cnt;
};

#endif // PACKETDETAILDIALOG_H
