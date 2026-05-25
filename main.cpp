#include "mainwindow.h"
#include "interfacedialog.h"
#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);

    InterfaceDialog dialog;

    // Вызываем exec(). Если пользователь выбрал интерфейс (двойной клик),
    // dialog.exec() вернет значение QDialog::Accepted (равное 1)
    if (dialog.exec() == QDialog::Accepted) {
        // Достаем выбранный интерфейс
        std::pair<QString, QString> interfaceData = dialog.selectedInterfaceName();
        QString selectedNet = interfaceData.first;
        QString selectedDescription = interfaceData.second;

        // Создаем главное окно, передавая туда интерфейс
        MainWindow w(selectedNet, selectedDescription);
        w.showMaximized();

        // Запускаем основной цикл приложения
        return a.exec();
    }

    // Если пользователь просто закрыл окно выбора интерфейса на "крестик",
    // приложение плавно завершит работу без открытия главного окна
    return 0;
}
