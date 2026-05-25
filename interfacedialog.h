#ifndef INTERFACEDIALOG_H
#define INTERFACEDIALOG_H

#include <QDialog>
#include <QStringList>
#include <QListWidgetItem>

QT_BEGIN_NAMESPACE
namespace Ui { class InterfaceDialog; }
QT_END_NAMESPACE

class InterfaceDialog : public QDialog {
    Q_OBJECT

public:
    explicit InterfaceDialog(QWidget *parent = nullptr);
    ~InterfaceDialog();

    // Метод, чтобы забрать выбранный интерфейс в main.cpp
    std::pair<QString, QString> selectedInterfaceName() const;

private slots:
    // Слот, который сработает при двойном клике
    void on_interfaceList_itemDoubleClicked(QListWidgetItem *item);

private:
    Ui::InterfaceDialog *ui;
    QStringList m_interfaceNames;           // Здесь храним реальные имена вроде
    QStringList m_interfaceDescriptions;    // Человеческие описания интерфейсов
    QString m_selectedInterfaceName;        // Сюда сохраним выбор пользователя
    QString m_selectedInterfaceDescription;
};

#endif // INTERFACEDIALOG_H
