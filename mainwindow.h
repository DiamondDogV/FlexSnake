#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QTableWidgetItem>
#include "packetsniffer.h"
#include "packetdetaildialog.h"
#include <pcap.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(const QString &interfaceName, const QString &interfaceDesciption, QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_solidButton_clicked();
    void on_liquidButton_clicked();
    void on_solidusButton_clicked();

    void onPacketCaptured(const PacketData &data);

    void applyCurrentFilters();
    void on_btnSortOrder_toggled(bool checked);
    void on_txtIpFilter_editingFinished();
    void on_cmbProtocolFilter_currentTextChanged(const QString &arg1);
    void on_txtLengthFilter_editingFinished();

    void on_packetTable_itemClicked(QTableWidgetItem *item);
    void on_packetTable_itemDoubleClicked(QTableWidgetItem *item);
    void on_loadButton_clicked();

private:
    Ui::MainWindow *ui;

    QString m_interfaceName;
    QThread *m_snifferThread = nullptr;
    PacketSniffer *m_sniffer = nullptr;

    void setupUiCustomizations();
    bool matchesFilters(const PacketData &data);
    void fillHexDump(const QByteArray &bytes);
    void fillProtocolTree(const PacketData &data);
};

#endif // MAINWINDOW_H
