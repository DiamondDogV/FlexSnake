#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QMessageBox>
#include <QFileDialog>
#include <QDateTime>
#include <QColor>
#include <QRegularExpression>
#include <QTextCharFormat>

MainWindow::MainWindow(const QString &interfaceName, const QString &interfaceDesciption, QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    m_interfaceName(interfaceName)
{
    ui->setupUi(this);

    setWindowTitle("FlexSnake — " + interfaceDesciption);
    setupUiCustomizations();
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::setupUiCustomizations() {
    // настройка фильтров
    QStringList protocols = {"All", "TCP", "UDP", "Other"};
    ui->cmbProtocolFilter->addItems(protocols);

    // кнопки разделители

    // настройка packetTable
    QStringList headers = { "№", "Time", "IP Source", "IP Dest", "Protocol", "Length", "Info" };
    ui->packetTable->setColumnCount(headers.size());
    ui->packetTable->setHorizontalHeaderLabels(headers);

    // Настраиваем поведение колонок при изменении ширины окна
    QHeaderView *header = ui->packetTable->horizontalHeader();
    header->resizeSection(0, 70);
    header->resizeSection(1, 170);
    header->resizeSection(2, 200);
    header->resizeSection(3, 200);
    header->resizeSection(4, 150);
    header->resizeSection(5, 100);
    for (int i=0; i<6; i++) {
        header->setSectionResizeMode(i, QHeaderView::Interactive);
    }
    header->setSectionResizeMode(6, QHeaderView::Stretch);

    // настройка protocolTree
    // Задаем один общий заголовок для дерева разбора
    ui->protocolTree->setHeaderLabel("OSI details");

    // настройка hexDumpField
    // моноширинный шрифт
    QFont monoFont("Courier New"); // Consolas Monospace
    monoFont.setPointSize(10);
    monoFont.setStyleHint(QFont::TypeWriter);
    ui->hexDumpField->setFont(monoFont);
}







                                                                                                                                            //пауза пуск стоп
void MainWindow::on_solidButton_clicked()
{
    // Переключаем доступность кнопок управления
    ui->solidButton->setEnabled(false);
    ui->liquidButton->setEnabled(true);
    ui->solidusButton->setEnabled(true);

    if (m_sniffer) {
        m_sniffer->setRunning(false); // Пакеты в фоновом режиме будут отбрасываться
    }
}

void MainWindow::on_liquidButton_clicked()
{
    // Переключаем доступность кнопок управления
    ui->solidButton->setEnabled(true);
    ui->liquidButton->setEnabled(false);
    ui->solidusButton->setEnabled(false);

    // Если поток еще ни разу не запускался — создаем и запускаем его
    if (!m_snifferThread) {
        m_snifferThread = new QThread(this);
        m_sniffer = new PacketSniffer(m_interfaceName);
        m_sniffer->moveToThread(m_snifferThread);

        // Связываем сигнал получения пакета с функцией вывода в таблицу
        qRegisterMetaType<PacketData>("PacketData");
        connect(m_sniffer, &PacketSniffer::packetCaptured, this, &MainWindow::onPacketCaptured);

        // Связываем запуск потока с методом начала захвата pcap
        connect(m_snifferThread, &QThread::started, m_sniffer, &PacketSniffer::startSniffing);

        // Корректное удаление объектов при закрытии программы
        connect(m_snifferThread, &QThread::finished, m_sniffer, &QObject::deleteLater);
        connect(m_snifferThread, &QThread::finished, m_snifferThread, &QObject::deleteLater);

        m_snifferThread->start(); // Запуск фонового потока
    } else {
        // Если поток уже работает, но был на Паузе — просто разрешаем обработку пакетов
        m_sniffer->setRunning(true);
    }
}

void MainWindow::on_solidusButton_clicked()
{
    // Переключаем доступность кнопок управления
    ui->solidButton->setEnabled(false);
    ui->liquidButton->setEnabled(true);
    ui->solidusButton->setEnabled(false);

    // Полностью останавливаем фоновый поток
    if (m_snifferThread) {
        m_snifferThread->quit();
        m_snifferThread->wait(); // Ждем завершения pcap_loop
        m_snifferThread = nullptr;
        m_sniffer = nullptr;
    }

    // Очищаем таблицу пакетов для нового сеанса захвата
    ui->packetTable->setRowCount(0);
}







                                                                                                                                    //вывод пакета и фильтры
void MainWindow::onPacketCaptured(const PacketData &data) {
    // Получаем индекс новой строки
    int rowCount = ui->packetTable->rowCount();
    int insertRow = rowCount; // По умолчанию добавляем в конец

    // Проверяем кнопку сортировки/направления
    bool insertAtTop = ui->btnSortOrder->isChecked();
    if (insertAtTop) {
        insertRow = 0; // Добавляем на самую первую строчку
    }
    ui->packetTable->insertRow(insertRow);

    // Создаем элементы (ячейки) для каждой колонки
    QTableWidgetItem *itemNum   = new QTableWidgetItem(QString::number(rowCount + 1));
    QTableWidgetItem *itemTime  = new QTableWidgetItem(data.time);
    QTableWidgetItem *itemSrc   = new QTableWidgetItem(data.srcIp);
    QTableWidgetItem *itemDst   = new QTableWidgetItem(data.dstIp);
    QTableWidgetItem *itemProto = new QTableWidgetItem(data.protocol);
    QTableWidgetItem *itemLen   = new QTableWidgetItem(QString::number(data.length));
    QTableWidgetItem *itemInfo  = new QTableWidgetItem(data.info);

    // Выравниваем системные поля
    itemNum->setTextAlignment(Qt::AlignRight);
    itemNum->setTextAlignment(Qt::AlignVCenter);
    itemTime->setTextAlignment(Qt::AlignLeft);
    itemTime->setTextAlignment(Qt::AlignVCenter);
    itemProto->setTextAlignment(Qt::AlignCenter);
    itemLen->setTextAlignment(Qt::AlignRight);
    itemLen->setTextAlignment(Qt::AlignVCenter);

    // Раскрашиваем
    QColor rowColor;
    if (data.protocol == "TCP") {
        rowColor = QColor(230, 230, 250); // Светло-лавандовый для TCP
    } else if (data.protocol == "UDP") {
        rowColor = QColor(218, 247, 166); // Светло-зеленый для UDP
    } else {
        rowColor = QColor(255, 228, 225); // Розоватый для других
    }

    // Применяем цвет фона ко всем ячейкам созданной строки
    itemNum->setBackground(rowColor);
    itemTime->setBackground(rowColor);
    itemSrc->setBackground(rowColor);
    itemDst->setBackground(rowColor);
    itemProto->setBackground(rowColor);
    itemLen->setBackground(rowColor);
    itemInfo->setBackground(rowColor);

    // Вставляем ячейки в таблицу
    ui->packetTable->setItem(insertRow, 0, itemNum);
    ui->packetTable->setItem(insertRow, 1, itemTime);
    ui->packetTable->setItem(insertRow, 2, itemSrc);
    ui->packetTable->setItem(insertRow, 3, itemDst);
    ui->packetTable->setItem(insertRow, 4, itemProto);
    ui->packetTable->setItem(insertRow, 5, itemLen);
    ui->packetTable->setItem(insertRow, 6, itemInfo);

    itemNum->setData(Qt::UserRole, QVariant::fromValue(data));

    if (!matchesFilters(data)) {
        ui->packetTable->setRowHidden(insertRow, true); // Пакет перехвачен, но скрыт с глаз
    } else if (!insertAtTop) {
        ui->packetTable->scrollToBottom(); // Скроллим вниз, только если добавляем в конец
    }
}

bool MainWindow::matchesFilters(const PacketData &data) {
    // 1. Фильтр по IP (ищет совпадение в Source ИЛИ Destination)
    QString ipFilter = ui->txtIpFilter->text().trimmed();
    if (!ipFilter.isEmpty()) {
        if (data.srcIp != ipFilter && data.dstIp != ipFilter) {
            return false;
        }
    }

    // 2. Фильтр по Протоколу
    QString protoFilter = ui->cmbProtocolFilter->currentText();
    if (protoFilter != "All") {
        if (data.protocol != protoFilter) {
            return false;
        }
    }

    // 3. Фильтр по Длине (Обработка знаков >, <, >=, <=, =)
    QString lenFilter = ui->txtLengthFilter->text().trimmed();
    if (!lenFilter.isEmpty()) {
        // Регулярное выражение разделяет знак операции и число цифр
        QRegularExpression re("^([><]=?|=)(\\d+)$");
        QRegularExpressionMatch match = re.match(lenFilter);

        if (match.hasMatch()) {
            QString op = match.captured(1);
            int targetLen = match.captured(2).toInt();
            int currentLen = data.length;

            if (op == ">" && !(currentLen > targetLen)) return false;
            else if (op == "<" && !(currentLen < targetLen)) return false;
            else if (op == ">=" && !(currentLen >= targetLen)) return false;
            else if (op == "<=" && !(currentLen <= targetLen)) return false;
            else if ((op == "=" || op.isEmpty()) && !(currentLen == targetLen)) return false;
        }
    }

    return true;
}

void MainWindow::applyCurrentFilters() {
    int rows = ui->packetTable->rowCount();
    for (int i = 0; i < rows; ++i) {
        // Достаем структуру сохраненных данных из ячейки этой строки
        QTableWidgetItem *item = ui->packetTable->item(i, 0);
        if (item) {
            PacketData data = item->data(Qt::UserRole).value<PacketData>();

            // Если подходит под фильтры — показываем, если нет — скрываем
            ui->packetTable->setRowHidden(i, !matchesFilters(data));
        }
    }
}

void MainWindow::on_btnSortOrder_toggled(bool checked)
{
    if (checked) {
        ui->btnSortOrder->setText("🠅");
    } else {
        ui->btnSortOrder->setText("🠇");
    }
}
void MainWindow::on_txtIpFilter_editingFinished()
{
    applyCurrentFilters();
}
void MainWindow::on_cmbProtocolFilter_currentTextChanged(const QString &arg1)
{
    applyCurrentFilters();
}
void MainWindow::on_txtLengthFilter_editingFinished()
{
    applyCurrentFilters();
}






                                                                                                                                                //доп инфо
// Функция для генерации красивого HEX-дампа
void MainWindow::fillHexDump(const QByteArray &bytes) {
    ui->hexDumpField->clear();

    QString dumpStr;
    int size = bytes.size();

    for (int i = 0; i < size; i += 16) {
        // смещение
        dumpStr += QString("%1    ").arg(i, 4, 16, QChar('0')).toUpper();

        // по 16 в строке, с разделителем посередине
        for (int j = 0; j < 16; ++j) {
            if (i + j < size) {
                dumpStr += QString("%1 ").arg(static_cast<unsigned char>(bytes[i + j]), 2, 16, QChar('0')).toUpper();
            } else {
                dumpStr += "   "; // Пропуски, если пакет кончился
            }
            if (j == 7) dumpStr += " "; // Дополнительный пробел между 8-м и 9-м байтом
        }

        dumpStr += "       ";

        // ASCII символы
        for (int j = 0; j < 16; ++j) {
            if (i + j < size) {
                char ch = bytes[i + j];
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

    ui->hexDumpField->setPlainText(dumpStr);
}

// Функция заполнения дерева протоколов
void MainWindow::fillProtocolTree(const PacketData &data) {
    ui->protocolTree->clear();
    ui->protocolTree->setHeaderLabel("Packet analysis");

    // Лямбда-функция для создания красивой строки с границами байт и для MAC адресов
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
    QTreeWidgetItem *frameItem = new QTreeWidgetItem(ui->protocolTree);
    frameItem->setText(0, QString("Frame: %1 byte captured в %2, %3").arg(data.length).arg(data.time).arg(getRangeStr(0, data.length)));

    // 2. Уровень Ethernet (Сырые данные мак-адресов в инфо не прокидывали, покажем общие данные)
    QTreeWidgetItem *ethItem = new QTreeWidgetItem(ui->protocolTree);
    ethItem->setText(0, QString("Ethernet II, %1").arg(getRangeStr(currentOffset, data.ethLen)));
    new QTreeWidgetItem(ethItem, QStringList() << "Type of protocol: " + data.protocol);
    currentOffset += data.ethLen;
    QString destMac = getMacStr(data.rawData, currentOffset);
    QString srcMac = getMacStr(data.rawData, currentOffset + 6);
    new QTreeWidgetItem(ethItem, QStringList() << "Source MAC: " + srcMac);
    new QTreeWidgetItem(ethItem, QStringList() << "Destination MAC: " + destMac);

    // 3. Уровень IP
    if (data.srcIp != "N/A") {
        QTreeWidgetItem *ipItem = new QTreeWidgetItem(ui->protocolTree);
        ipItem->setText(0, QString("Internet Protocol Version 4, %1").arg(getRangeStr(currentOffset, data.ipLen)));
        currentOffset += data.ipLen;
        new QTreeWidgetItem(ipItem, QStringList() << "Source IP: " + data.srcIp);
        new QTreeWidgetItem(ipItem, QStringList() << "Destination IP: " + data.dstIp);
        new QTreeWidgetItem(ipItem, QStringList() << QString("Length of IP header: %1 bytes").arg(data.ipLen));
    }

    // 4. Уровень Транспортный (TCP / UDP)
    if (data.protocol == "TCP" || data.protocol == "UDP") {
        QTreeWidgetItem *transItem = new QTreeWidgetItem(ui->protocolTree);
        transItem->setText(0, QString("%1 Protocol, %2").arg(data.protocol).arg(getRangeStr(currentOffset, data.transLen)));
        currentOffset += data.transLen;

        // Извлекаем порты из Info строки (там обычно написано "Порты: X -> Y")
        new QTreeWidgetItem(transItem, QStringList() << data.info);
    }

    // 5. Уровень Payload (Полезная нагрузка / Данные приложения)
    int payloadLen = data.length - currentOffset;
    if (payloadLen > 0) {
        QTreeWidgetItem *payloadItem = new QTreeWidgetItem(ui->protocolTree);
        payloadItem->setText(0, QString("Data / Payload, %1").arg(getRangeStr(currentOffset, payloadLen)));
    }

    ui->protocolTree->expandAll(); // Разворачиваем все дерево сразу
}

void MainWindow::on_packetTable_itemClicked(QTableWidgetItem *item)
{
    if (!item) return;

    int row = item->row();
    // Достаем скрытые данные из первой ячейки строки
    QTableWidgetItem *firstItem = ui->packetTable->item(row, 0);
    if (!firstItem) return;
    PacketData data = firstItem->data(Qt::UserRole).value<PacketData>();

    // Заполняем виджеты на главном экране
    fillProtocolTree(data);
    fillHexDump(data.rawData);
}







                                                                                                                                        //загрузка сохранение
void MainWindow::on_packetTable_itemDoubleClicked(QTableWidgetItem *item)
{
    if (!item) return;

    int row = item->row();
    QTableWidgetItem *firstItem = ui->packetTable->item(row, 0);
    if (!firstItem) return;
    PacketData data = firstItem->data(Qt::UserRole).value<PacketData>();

    // Вызываем детальное окно
    PacketDetailDialog *detailDialog = new PacketDetailDialog(data, this);
    detailDialog->setAttribute(Qt::WA_DeleteOnClose); // Окно само удалит память при закрытии
    detailDialog->show();
}

void MainWindow::on_loadButton_clicked()
{
    // 1. Открываем диалог выбора файла
    QString filePath = QFileDialog::getOpenFileName(this, tr("Открыть файл PCAP"), "", tr("PCAP Files (*.pcap);;All Files (*)"));
    if (filePath.isEmpty()) return;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 2. Открываем pcap-файл для чтения
    pcap_t *handle = pcap_open_offline(filePath.toLocal8Bit().constData(), errbuf);
    if (!handle) {
        QMessageBox::critical(this, tr("Ошибка"), tr("Не удалось открыть PCAP файл: %1").arg(errbuf));
        return;
    }

    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    // 3. Читаем первый пакет из файла
    int res = pcap_next_ex(handle, &header, &pkt_data);
    if (res == 1) {
        // Извлекаем сырые байты пакета
        QByteArray raw(reinterpret_cast<const char*>(pkt_data), header->caplen);

        PacketData data;
        data.length = header->len;
        data.rawData = raw;

        // Форматируем время пакета
        QDateTime dateTime = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec);
        data.time = dateTime.toString("yyyy-MM-dd HH:mm:ss") + QString(".%1").arg(header->ts.tv_usec, 6, 10, QChar('0'));

        // Базовый разбор сетевых заголовков
        if (raw.size() >= 14) {
            // Разбор типа Ethernet
            unsigned short ethType = ntohs(*reinterpret_cast<const unsigned short*>(pkt_data + 12));

            if (ethType == 0x0800 && raw.size() >= 34) { // IPv4
                const u_char *ip = pkt_data + 14;
                int ip_hdr_len = (ip[0] & 0x0F) * 4;

                data.srcIp = QString("%1.%2.%3.%4").arg(ip[12]).arg(ip[13]).arg(ip[14]).arg(ip[15]);
                data.dstIp = QString("%1.%2.%3.%4").arg(ip[16]).arg(ip[17]).arg(ip[18]).arg(ip[19]);

                unsigned char ipProto = ip[9];
                const u_char *transport = ip + ip_hdr_len;

                int srcPort = ntohs(*reinterpret_cast<const unsigned short*>(transport));
                int dstPort = ntohs(*reinterpret_cast<const unsigned short*>(transport + 2));

                if (ipProto == 6) {
                    data.protocol = "TCP";
                    data.info = QString("%1 -> %2").arg(srcPort).arg(dstPort);
                } else if (ipProto == 17) {
                    data.protocol = "UDP";
                    data.info = QString("%1 -> %2").arg(srcPort).arg(dstPort);
                } else {
                    data.protocol = "Other";
                    data.info = QString("Protocol Type: 0x%1").arg(ipProto, 2, 16, QChar('0')).toUpper();
                }
            } else {
                data.protocol = "Other";
                data.info = QString("EtherType: 0x%1").arg(ethType, 4, 16, QChar('0')).toUpper();
            }
        }

        // 4. Закрываем pcap дескриптор, так как данные уже скопированы в структуру data
        pcap_close(handle);

        // 5. Создаем и открываем модальное окно детального анализа пакета
        PacketDetailDialog *detailDialog = new PacketDetailDialog(data, this);
        detailDialog->setAttribute(Qt::WA_DeleteOnClose);
        detailDialog->show();
    } else {
        pcap_close(handle);
        QMessageBox::warning(this, tr("Внимание"), tr("Файл пуст или не содержит корректных пакетов."));
    }
}
