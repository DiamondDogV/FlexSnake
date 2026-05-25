#include "packetdetaildialog.h"
#include <QVBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QMessageBox>
#include <QFont>
#include <pcap.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

int PacketDetailDialog::file_cnt = 0;

PacketDetailDialog::PacketDetailDialog(const PacketData &data, QWidget *parent)
    : QDialog(parent), m_packetData(data)
{
    setWindowTitle(QString("Packet detailed").arg(m_packetData.time));
    resize(2400, 1300);

    setupUiElements();

    fillProtocolTree();
    fillHexDump();
}

PacketDetailDialog::~PacketDetailDialog() {
}

void PacketDetailDialog::setupUiElements() {
    // 1. Главный вертикальный layout для всего окна
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // 2. Создаем вертикальный сплиттер (разделитель)
    QSplitter *splitter = new QSplitter(Qt::Vertical, this);

    // 3. Создаем дерево протоколов
    m_treeWidget = new QTreeWidget(this);
    m_treeWidget->setHeaderLabel("Анализ протоколов");
    QFont treeFont = m_treeWidget->font();
    treeFont.setPointSize(14);
    m_treeWidget->setFont(treeFont);

    // 4. Создаем поле HEX-дампа
    m_hexEdit = new QTextEdit(this);
    m_hexEdit->setReadOnly(true);
    m_hexEdit->setLineWrapMode(QTextEdit::NoWrap);
    QFont hexFont("Courier New", 12);
    m_hexEdit->setFont(hexFont);

    // Добавляем дерево и хекс в сплиттер
    splitter->addWidget(m_treeWidget);
    splitter->addWidget(m_hexEdit);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 1);

    // Добавляем сплиттер в главный layout
    mainLayout->addWidget(splitter);

    // 5. Создаем кнопку загрузки в самом низу окна
    m_btnDownload = new QPushButton("Download (.pcap)", this);
    m_btnDownload->setMinimumHeight(80);
    m_btnDownload->setStyleSheet(
        "QPushButton { font-size: 36px; font-weight: bold; background-color: #2ea44f; color: white; border-radius: 4px; }"
        "QPushButton:hover { background-color: #2c974b; }"
        );

    mainLayout->addWidget(m_btnDownload);

    // Соединяем сигнал клика по кнопке со слотом сохранения файла
    connect(m_btnDownload, &QPushButton::clicked, this, &PacketDetailDialog::onDownloadClicked);
}

void PacketDetailDialog::fillProtocolTree() {
    m_treeWidget->clear();
    m_treeWidget->setHeaderLabel("Packet analysis");

    // Лямбда-функция для создания красивой строки с границами байт
    auto getRangeStr = [](int start, int length) -> QString {
        int end = start + length - 1;
        QString s2 = QString("%1").arg(start, 4, 16, QChar('0'));
        s2 = s2.toUpper();
        QString s3 = QString("%1").arg(end, 4, 16, QChar('0'));
        s3 = s3.toUpper();
        return QString("%1 bytes, from %2 to %3").arg(length).arg(s2).arg(s3);
    };
    auto getMacStr = [](const QByteArray &raw, int offset) -> QString {
        if (offset + 6 > raw.size()) return "00:00:00:00:00:00";
        QStringList bytes;
        for (int i = 0; i < 6; ++i) {
            bytes.append(QString("%1").arg(static_cast<unsigned char>(raw[offset + i]), 2, 16, QChar('0')).toUpper());
        }
        return bytes.join(":");
    };
    int currentOffset = 0;

    // 1. Уровень Frame (Общая инфо)
    QTreeWidgetItem *frameItem = new QTreeWidgetItem(m_treeWidget);
    frameItem->setText(0, QString("Frame: %1 byte captured в %2, %3").arg(m_packetData.length).arg(m_packetData.time).arg(getRangeStr(0, m_packetData.length)));

    // 2. Уровень Ethernet (Сырые данные мак-адресов в инфо не прокидывали, покажем общие данные)
    QTreeWidgetItem *ethItem = new QTreeWidgetItem(m_treeWidget);
    ethItem->setText(0, QString("Ethernet II, %1").arg(getRangeStr(currentOffset, m_packetData.ethLen)));
    new QTreeWidgetItem(ethItem, QStringList() << "Type of protocol: " + m_packetData.protocol);
    currentOffset += m_packetData.ethLen;
    QString destMac = getMacStr(m_packetData.rawData, currentOffset);
    QString srcMac = getMacStr(m_packetData.rawData, currentOffset + 6);
    new QTreeWidgetItem(ethItem, QStringList() << "Source MAC: " + srcMac);
    new QTreeWidgetItem(ethItem, QStringList() << "Destination MAC: " + destMac);

    // 3. Уровень IP
    if (m_packetData.srcIp != "N/A") {
        QTreeWidgetItem *ipItem = new QTreeWidgetItem(m_treeWidget);
        ipItem->setText(0, QString("Internet Protocol Version 4, %1").arg(getRangeStr(currentOffset, m_packetData.ipLen)));
        currentOffset += m_packetData.ipLen;
        new QTreeWidgetItem(ipItem, QStringList() << "Source IP: " + m_packetData.srcIp);
        new QTreeWidgetItem(ipItem, QStringList() << "Destination IP: " + m_packetData.dstIp);
        new QTreeWidgetItem(ipItem, QStringList() << QString("Length of IP header: %1 bytes").arg(m_packetData.ipLen));
    }

    // 4. Уровень Транспортный (TCP / UDP)
    if (m_packetData.protocol == "TCP" || m_packetData.protocol == "UDP") {
        QTreeWidgetItem *transItem = new QTreeWidgetItem(m_treeWidget);
        transItem->setText(0, QString("%1 Protocol, %2").arg(m_packetData.protocol).arg(getRangeStr(currentOffset, m_packetData.transLen)));
        currentOffset += m_packetData.transLen;

        // Извлекаем порты из Info строки (там обычно написано "Порты: X -> Y")
        new QTreeWidgetItem(transItem, QStringList() << m_packetData.info);
    }

    // 5. Уровень Payload (Полезная нагрузка / Данные приложения)
    int payloadLen = m_packetData.length - currentOffset;
    if (payloadLen > 0) {
        QTreeWidgetItem *payloadItem = new QTreeWidgetItem(m_treeWidget);
        payloadItem->setText(0, QString("Data / Payload, %1").arg(getRangeStr(currentOffset, payloadLen)));
    }

    m_treeWidget->expandAll(); // Разворачиваем все дерево сразу
}

void PacketDetailDialog::fillHexDump() {
    m_hexEdit->clear();

    QString dumpStr;
    int size = m_packetData.rawData.size();

    for (int i = 0; i < size; i += 16) {
        // смещение
        dumpStr += QString("%1    ").arg(i, 4, 16, QChar('0')).toUpper();

        // по 16 в строке, с разделителем посередине
        for (int j = 0; j < 16; ++j) {
            if (i + j < size) {
                dumpStr += QString("%1 ").arg(static_cast<unsigned char>(m_packetData.rawData[i + j]), 2, 16, QChar('0')).toUpper();
            } else {
                dumpStr += "   "; // Пропуски, если пакет кончился
            }
            if (j == 7) dumpStr += " "; // Дополнительный пробел между 8-м и 9-м байтом
        }

        dumpStr += "               ";

        // ASCII символы
        for (int j = 0; j < 16; ++j) {
            if (i + j < size) {
                char ch = m_packetData.rawData[i + j];
                // только печатные символы, остальные точка
                if (ch >= 32 && ch <= 126) {
                    dumpStr += ch;
                } else {
                    dumpStr += ".";
                }
            }
            if (j == 7) dumpStr += " ";
        }
        dumpStr += "\n";
    }

    m_hexEdit->setPlainText(dumpStr);
}

void PacketDetailDialog::onDownloadClicked() {
    QString defaultName = QString("packet_%1.pcap").arg(file_cnt++);
    QString filePath = QFileDialog::getSaveFileName(this, "Сохранить пакет как PCAP", defaultName, "PCAP Files (*.pcap)");

    if (filePath.isEmpty()) return;

    pcap_t *deadPcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!deadPcap) {
        QMessageBox::critical(this, "Ошибка", "Не удалось инициализировать pcap_open_dead");
        return;
    }

    pcap_dumper_t *dumper = pcap_dump_open(deadPcap, filePath.toLocal8Bit().constData());
    if (!dumper) {
        QMessageBox::critical(this, "Ошибка", QString("Не удалось создать файл: %1").arg(pcap_geterr(deadPcap)));
        pcap_close(deadPcap);
        return;
    }

    struct pcap_pkthdr header;
    struct timeval tv;
#ifdef _WIN32
    union { long long ns100; FILETIME ft; } now;
    GetSystemTimeAsFileTime(&now.ft);
    tv.tv_usec = (long)((now.ns100 / 10LL) % 1000000LL);
    tv.tv_sec = (long)((now.ns100 - 116444736000000000LL) / 10000000LL);
#else
    gettimeofday(&tv, nullptr);
#endif

    header.ts = tv;
    header.caplen = m_packetData.rawData.size();
    header.len = m_packetData.length;

    pcap_dump(reinterpret_cast<u_char*>(dumper), &header, reinterpret_cast<const u_char*>(m_packetData.rawData.constData()));

    pcap_dump_close(dumper);
    pcap_close(deadPcap);

    QMessageBox::information(this, "Успех", "Пакет успешно экспортирован в .pcap файл!");
}
