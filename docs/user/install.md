# Установка и удаление

Здесь — как поставить OpenNCALayer на Windows, macOS или Linux, что установщик делает на вашем компьютере и как программу удалить. Что делать после установки — в [`desktop.md`](desktop.md) и [`browser-extension.md`](browser-extension.md).

## Быстрый старт

1. Скачайте установщик для своей системы со страницы [«Загрузка»](https://arynyklas.github.io/OpenNCALayer/download/) или из [Releases](https://github.com/arynyklas/OpenNCALayer/releases).
2. Запустите его (подробности по системам — ниже).
3. Поставьте [расширение браузера](browser-extension.md).

Установщики работают без прав администратора и ставят программу только для вас (исключение — `.pkg` в `/Applications`). Установщики не подписаны, поэтому при первом запуске Windows покажет предупреждение SmartScreen, а macOS — Gatekeeper.

Ваши настройки, сертификат и журналы лежат в отдельном каталоге данных. Он остаётся при обновлении и при удалении программы.

## Какой файл взять

| Система | Файл |
|---|---|
| Windows 10 и 11, 64 бита | `openncalayer-<версия>-win-x64-setup.exe` |
| Windows 10 и 11, 32 бита | `openncalayer-<версия>-win-x86-setup.exe` |
| Windows 7 SP1, 64 или 32 бита | `openncalayer-<версия>-win7-x64-setup.exe` или `…-win7-x86-setup.exe` ([подробнее](#windows-7)) |
| macOS (Intel и Apple Silicon) | `openncalayer-<версия>-osx.pkg` или `openncalayer-<версия>-osx.zip` |
| Linux x86-64 | `openncalayer-<версия>-linux-x64.AppImage` |
| Arch Linux | `openncalayer-bin-*-x86_64.pkg.tar.zst` |

Версии с суффиксом (например, `-rc.1`) — предварительные.

Чтобы проверить скачанный файл, сравните его с `SHA256SUMS` из того же релиза. Происхождение файла проверяет команда `gh attestation verify <файл> --repo arynyklas/OpenNCALayer`.

В Releases есть и другие файлы: архивы без установщика (`.zip` для Windows), расширения браузера, список зависимостей (SBOM), пакеты для автообновления. Каждый файл описан на странице «Загрузка».

## Установка

### Windows 10 и 11

1. Запустите `…-win-x64-setup.exe` (для 32-битной системы — `…-win-x86-setup.exe`). Установщик сам откажется ставиться на Windows 7 и 8.
2. Программа встанет в `%LOCALAPPDATA%\OpenNCALayer`, в меню «Пуск» появится «OpenNCALayer», и она сразу запустится.

Удаление: «Параметры» → «Приложения» (или «Программы и компоненты»). Удаляется весь каталог `%LOCALAPPDATA%\OpenNCALayer`.

### macOS

1. Откройте `openncalayer-<версия>-osx.pkg`. Программа встанет в `/Applications` (или в `~/Applications`, если выбрать «Установить только для меня») и запустится.
2. Вместо `.pkg` можно взять `openncalayer-<версия>-osx.zip`: перетащите `OpenNCALayer.app` в «Программы» и запустите.

Сборка не подписана Apple. Поэтому Gatekeeper откажется открывать скачанный файл. Разрешите его в «Системные настройки» → «Конфиденциальность и безопасность» → «Всё равно открыть» и повторите открытие. Этот путь на настоящем Mac человеком не проверялся.

Удаление:
1. Выполните в Терминале `"/Applications/OpenNCALayer.app/Contents/MacOS/openncalayer" integration uninstall` (при установке «только для меня» — `"$HOME/Applications/OpenNCALayer.app/Contents/MacOS/openncalayer" integration uninstall`).
2. Перенесите приложение в Корзину.

Проверено автоматически на Mac с Apple Silicon и с Intel: установка `.pkg`, запуск, самопроверка по TLS и удаление. Не проверено: работа расширения в браузерах на Mac, значок в строке меню и подпись ключом на Mac.

### Linux

1. Скачайте `openncalayer-<версия>-linux-x64.AppImage`, сделайте его исполняемым (`chmod +x`) и запустите. Работает на системах с glibc 2.28 и новее (Debian 10, Ubuntu 18.10, RHEL, AlmaLinux и Rocky 8, Fedora 29, Arch и новее).
2. Нужен графический сеанс (X11 или Wayland). Без `DISPLAY` или `WAYLAND_DISPLAY` программа сообщит об этом и завершится с кодом 1.
3. AppImage требует FUSE 2. В Ubuntu 22.04 и новее её нет по умолчанию: поставьте `sudo apt install libfuse2` (в Ubuntu 24.04 пакет называется `libfuse2t64`). Или запустите файл с ключом `--appimage-extract-and-run`: он работает без FUSE.

Удаление: выполните `openncalayer-<версия>-linux-x64.AppImage integration uninstall` и удалите файл.

### Arch Linux

Можно взять AppImage (он обновляется сам) или пакет:

```sh
sha256sum -c --ignore-missing SHA256SUMS
sudo pacman -U ./openncalayer-bin-*.pkg.tar.zst
```

Программы лягут в `/usr/lib/openncalayer/`, команда называется `openncalayer`. Пакет сам не обновляется: новую версию ставьте так же вручную.

Удаление: выполните `openncalayer integration uninstall` от каждого пользователя, который запускал программу, затем `sudo pacman -R openncalayer-bin`.

### WinGet

Пока недоступен. Команды `winget install --id arynyklas.OpenNCALayer` ещё нет: пакет не принят в источник WinGet. Ставьте обычный установщик. Как готовится пакет — в [`docs/dev/winget.md`](../dev/winget.md).

### Архив без установщика

Распакуйте архив и запустите `openncalayer run`. Чтобы встроить распакованную копию в систему так же, как это делает установщик, выполните `openncalayer integration install`. Такая копия сама не обновляется.

## Что установка делает для вас

Установщик Windows и `.pkg` делают это при установке. Остальные варианты (AppImage, пакет pacman, `.zip`) — при первом запуске программы.

- Регистрирует связь с браузером — то же, что `openncalayer nm install` ([подробнее](browser-extension.md)).
- Включает автозапуск OpenNCALayer и записывает `"autostart": true` в `settings.json`.
- Отключает автозапуск оригинального NCALayer у вас. Сам оригинал не удаляется, это можно отменить ([подробнее](desktop.md#оригинальный-ncalayer)). Запись для всех пользователей (`HKLM\…\Run`) не трогается.
- Записывает файл `installation.json` в каталог данных: какая версия встроена и откуда.

Сертификат для браузера установка не ставит. Его вы настраиваете сами в [мастере](desktop.md#мастер-tls).

**Повторная установка и обновление.** Каждый шаг выполняется один раз. Повторный запуск установщика доделывает только то, что не сделано. Обновление копирует связь с браузером заново и обновляет пути, но не включает снова то, что вы отключили: автозапуск, регистрацию расширения, возврат оригинала.

**Удаление** убирает только то, что поставила программа: связь с браузером, её настройки, ключи реестра браузеров и наш автозапуск. Автозапуск оригинала возвращается, если вы не вернули его раньше. Каталог данных остаётся.

### Если установка не закончилась

Установщик Windows предупредит об этом, `.pkg` покажет ошибку. Причины ищите в журнале (каталог `logs/` внутри каталога данных). Невыполненный шаг повторится при следующем запуске программы.

Состояние смотрите командой `openncalayer integration status`. Она показывает шаги и подсказку, что делать, и возвращает код 1, если установка не закончена. Те же действия вручную: `openncalayer integration install` и `openncalayer integration uninstall`.

Если при удалении в Windows что-то осталось, выполните `openncalayer integration uninstall` из архива той же версии (например, `openncalayer-<версия>-x86_64-pc-windows-msvc.zip`).

## Windows 7

Для Windows 7 SP1 есть отдельные архивы `openncalayer-<версия>-win7-x64.zip` и `openncalayer-<версия>-win7-x86.zip` и установщики `…-win7-*-setup.exe`. Visual C++ Redistributable не нужен.

В архиве рядом с `openncalayer.exe` лежат две маленькие библиотеки: `combase.dll` и `api-ms-win-core-winrt-error-l1-1-0.dll`. В Windows 7 нет нужных системных функций, и эти библиотеки их заменяют. Распаковывайте архив целиком и держите всё в одном каталоге. В Windows 8 и новее системные библиотеки используются вместо них, поэтому сборка для Windows 7 работает и на новых системах (проверено на Windows 11 и Windows Server 2025).

Браузеры для Windows 7: Firefox ESR 115 и Chrome 109 — последние версии, которые там работают. У Firefox ESR 115 есть свои ограничения расширения ([подробнее](browser-extension.md#отличия-и-ограничения-расширения)).

Что проверено: в лаборатории проекта на Windows 7 — архив и запуск программы, расширение в Chrome 109 и Firefox ESR 115, установщик с перезагрузкой и удаление.

## Сайт проекта

[arynyklas.github.io/OpenNCALayer](https://arynyklas.github.io/OpenNCALayer/) — на русском, казахском (`/kk/`) и английском (`/en/`):
- [«Плагины»](https://arynyklas.github.io/OpenNCALayer/plugins/) — каталог плагинов, перенесённых из оригинала: какой плагин что заменяет, версии и отличия от оригинала;
- [«Загрузка»](https://arynyklas.github.io/OpenNCALayer/download/) — последний релиз и предварительная версия;
- [«История оригинала»](https://arynyklas.github.io/OpenNCALayer/upstream/) — версии модулей оригинального NCALayer и их изменения.

## Вопросы и ошибки

Вопросы — в Telegram-чате [t.me/OpenNCALayer](https://t.me/OpenNCALayer) (ссылка есть и в окне «О программе»). Об ошибках пишите в [Issues](https://github.com/arynyklas/OpenNCALayer/issues). Приложите версию программы (окно «О программе»), систему и журнал. Ключи, пароли и документы не прикладывайте.
