#include "interfacedialog.h"
#include "ui_interfacedialog.h"
#include <pcap.h>
#include <QMessageBox>

InterfaceDialog::InterfaceDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InterfaceDialog)
{
    ui->setupUi(this);
    setWindowTitle("Выбор сетевого интерфейса");

    pcap_if_t *allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Получаем список устройств через Npcap
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        QMessageBox::critical(this, "Ошибка Npcap", QString("Не удалось получить список устройств: %1").arg(errbuf));
        return;
    }

    // Проходим по списку устройств
    for (pcap_if_t *d = allDevs; d != nullptr; d = d->next) {
        // Сохраняем реальное имя для pcap_open_live
        QString deviceName = QString::fromLocal8Bit(d->name);
        m_interfaceNames.append(deviceName);

        // Формируем красивое описание для пользователя
        QString description;
        if (d->description) {
            description = QString::fromLocal8Bit(d->description);
        } else {
            description = deviceName;
        }
        m_interfaceDescriptions.append(description);

        ui->interfaceList->addItem(description);
    }

    // Освобождаем память, выделенную Npcap
    pcap_freealldevs(allDevs);
}

InterfaceDialog::~InterfaceDialog() {
    delete ui;
}

void InterfaceDialog::on_interfaceList_itemDoubleClicked(QListWidgetItem *item) {
    // Получаем индекс строки, по которой кликнули
    int index = ui->interfaceList->row(item);
    if (index >= 0 && index < m_interfaceNames.size()) {
        m_selectedInterfaceName = m_interfaceNames[index]; // Запоминаем имя для pcap
        m_selectedInterfaceDescription = m_interfaceDescriptions[index];
        accept(); // Закрываем диалог с успешным результатом
    }
}

std::pair<QString, QString> InterfaceDialog::selectedInterfaceName() const {
    return std::make_pair(m_selectedInterfaceName, m_selectedInterfaceDescription);
}
