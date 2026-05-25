#include "packetsniffer.h"
#include <QDateTime>
#include <QList>
#include <QDebug>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// Сетевые структуры для разбора байт
struct eth_hdr {
    unsigned char  mac_dest[6];
    unsigned char  mac_src[6];
    unsigned short type;
};

struct ip_hdr {
    unsigned char  ver_ihl;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short flags;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short crc;
    unsigned char  ip_src[4];
    unsigned char  ip_dst[4];
};

struct trans_ports {
    unsigned short src_port;
    unsigned short dst_port;
};

PacketSniffer::PacketSniffer(const QString &interfaceName, QObject *parent)
    : QObject(parent), m_interfaceName(interfaceName), m_pcapHandle(nullptr), m_running(false) {}

PacketSniffer::~PacketSniffer() {
    if (m_pcapHandle) {
        pcap_breakloop(m_pcapHandle);
        pcap_close(m_pcapHandle);
    }
}

void PacketSniffer::setRunning(bool running) {
    m_running = running;
}

void PacketSniffer::startSniffing() {
    qDebug() << "Npcap version:" << pcap_lib_version();

    char errbuf[PCAP_ERRBUF_SIZE];

    // Открываем интерфейс для захвата
    m_pcapHandle = pcap_open_live(m_interfaceName.toStdString().c_str(), 65536, 1, 1000, errbuf);
    if (!m_pcapHandle) {
        emit errorOccurred(QString("Не удалось открыть интерфейс: %1").arg(errbuf));
        return;
    }

    m_running = true;

    // Запускаем бесконечный цикл pcap, передавая указатель на текущий объект (this) в качестве контекста
    pcap_loop(m_pcapHandle, 0, PacketSniffer::pcapPacketHandler, (u_char*)this);
}
void PacketSniffer::stopSniffing()
{
    if (m_pcapHandle) {
        pcap_breakloop(m_pcapHandle);
    }
    m_running = false;
}

// Статический колбэк pcap
void PacketSniffer::pcapPacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    // Восстанавливаем указатель на наш объект класса
    PacketSniffer *sniffer = reinterpret_cast<PacketSniffer*>(param);

    // Если нажата пауза — игнорируем пакеты, не отправляя их в GUI
    if (!sniffer->m_running) return;

    // 1. Время прихода пакета
    QString timeStr = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec).toString("hh:mm:ss");
    int milliseconds = header->ts.tv_usec / 1000;
    timeStr += QString(".%1").arg(milliseconds, 4, 10, QChar('0'));

    // 2. Разбор Ethernet
    const eth_hdr *eth = reinterpret_cast<const eth_hdr*>(pkt_data);
    if (ntohs(eth->type) != 0x0800) return; // Пропускаем всё, кроме IPv4 (например, ARP или IPv6)

    // 3. Разбор IP
    const ip_hdr *ip = reinterpret_cast<const ip_hdr*>(pkt_data + 14);
    int ip_len = (ip->ver_ihl & 0x0F) * 4;

    // 4. Разбор Транспортного уровня
    const trans_ports *tp = reinterpret_cast<const trans_ports*>(pkt_data + 14 + ip_len);

    // Заполняем структуру для отправки в главное окно
    PacketData data;
    data.time = timeStr;
    data.length = header->len;
    data.ipLen = ip_len;
    data.srcIp = QString("%1.%2.%3.%4").arg(ip->ip_src[0]).arg(ip->ip_src[1]).arg(ip->ip_src[2]).arg(ip->ip_src[3]);
    data.dstIp = QString("%1.%2.%3.%4").arg(ip->ip_dst[0]).arg(ip->ip_dst[1]).arg(ip->ip_dst[2]).arg(ip->ip_dst[3]);

    int srcPort = ntohs(tp->src_port);
    int dstPort = ntohs(tp->dst_port);

    if (ip->protocol == 6) {
        data.protocol = "TCP";
        data.info = QString("%1 -> %2").arg(srcPort).arg(dstPort);
        // У TCP размер заголовка хранится в поле Data Offset (высокие 4 бита 12-го байта заголовка TCP)
        const unsigned char *tcp_hdr_start = pkt_data + 14 + ip_len;
        int tcp_len = ((tcp_hdr_start[12] >> 4) & 0x0F) * 4;
        data.transLen = tcp_len;
    } else if (ip->protocol == 17) {
        data.protocol = "UDP";
        data.info = QString("%1 -> %2").arg(srcPort).arg(dstPort);
        data.transLen = 8;
    } else {
        data.protocol = "Other";
        data.info = QString("Protocol Type: %1").arg(ip->protocol);
        data.transLen = 0;
    }

    // Копируем сырые байты пакета целиком для HEX-дампа
    data.rawData = QByteArray(reinterpret_cast<const char*>(pkt_data), header->caplen);

    // Отправляем сигнал в GUI-поток
    emit sniffer->packetCaptured(data);
}
