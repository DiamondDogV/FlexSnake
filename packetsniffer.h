#ifndef PACKETSNIFFER_H
#define PACKETSNIFFER_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <pcap.h>

// Структура для передачи данных пакета в GUI
struct PacketData {
    QString time;
    QString srcIp;
    QString dstIp;
    QString protocol;
    int length;
    QString info;
    QByteArray rawData; // Сырые байты для HEX-дампа

    int ethLen = 14;      // Заголовок Ethernet всегда 14 байт
    int ipLen = 0;        // Размер IP-заголовка (вычисляется динамически)
    int transLen = 0;     // Размер TCP (20-60 байт) или UDP (всегда 8 байт)
};

// Регистрируем структуру в системе метатипов Qt, чтобы передавать между потоками
Q_DECLARE_METATYPE(PacketData)

class PacketSniffer : public QObject {
    Q_OBJECT
public:
    explicit PacketSniffer(const QString &interfaceName, QObject *parent = nullptr);
    ~PacketSniffer();

    void setRunning(bool running);

public slots:
    void startSniffing();
    void stopSniffing();

signals:
    void packetCaptured(const PacketData &data); // Сигнал для MainWindow
    void errorOccurred(const QString &errorMsg);

private:
    static void pcapPacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

    QString m_interfaceName;
    pcap_t *m_pcapHandle;
    bool m_running;
};

#endif // PACKETSNIFFER_H
