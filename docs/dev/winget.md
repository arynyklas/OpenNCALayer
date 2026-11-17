# WinGet: манифест и подача

Для мейнтейнера: как сделать манифест для опубликованного релиза и подать его в репозиторий `microsoft/winget-pkgs`, чтобы программу можно было поставить командой `winget install`. Команда `winget install --id arynyklas.OpenNCALayer --exact` заработает только после того, как Microsoft примет пакет (шаг 6 подачи ниже).

## Что WinGet устанавливает

WinGet запускает не обычный `…-setup.exe`, а `openncalayer-<версия>-win-<x64|x86>-winget-setup.exe`. Это маленькая обёртка `oncl-winget-setup`, внутри которой лежит неизменённый `Setup.exe` от Velopack. Работает только в Windows 10 версии 1809 и новее: Windows 7 в WinGet не заявлен. Как устроена обёртка — [`winget-installer.md`](winget-installer.md).

Обёртка нужна потому, что `Setup.exe` от Velopack делает две вещи, которые WinGet не выдерживает:
- при переустановке он без спроса завершает установленную программу, даже посреди подписи;
- если не выполнены prerequisites (то, что нужно поставить заранее), он выходит с кодом 0, ничего не поставив.

Оба действия происходят в самом `Setup.exe`, и параметрами `vpk pack` их не отключить. Поэтому обёртка просит запущенную программу «замереть», проверяет, что установка действительно прошла, и возвращает честный код возврата.

## Как сделать манифест

```sh
cargo xtask winget manifest --version 0.2.0
```

Версию пишите как в теге, без `v`. Команда:
- скачивает `SHA256SUMS` релиза `v<версия>` (или берёт файл из `--sums <путь>`);
- пишет в `target/winget` (другой каталог — `--out`) три файла схемы 1.12.0: `arynyklas.OpenNCALayer.yaml`, `….locale.en-US.yaml` и `….installer.yaml`.

В `installer.yaml` два установщика, `x64` и `x86`. Ссылки ведут на файлы этого релиза (`https://github.com/arynyklas/OpenNCALayer/releases/download/v<версия>/…`), SHA-256 берётся из `SHA256SUMS`. Установщик принимает только `--silent` (интерактивного режима нет). Код 4 («занято: идёт подпись») описан как `packageInUse`, а не как успех. Установка — для текущего пользователя (`Scope: user`), повышение прав запрещено. Манифест нигде не сохраняется в репозитории.

Проверка манифеста: `winget validate target/winget` (проверяет схему, а не установку).

## Что нужно до подачи

- Опубликован релиз **без суффикса** (`0.x.y`, не `-alpha.N`): в WinGet подаются только стабильные версии.
- Оба `winget-setup.exe` подписаны Authenticode: настроен SignPath, и в его настройках разрешён `*-winget-setup.exe` (см. [`winget-installer.md`](winget-installer.md), «Что сделать мейнтейнеру один раз»). Без подписи манифест не подавайте.
- Установка проверена в чистой виртуальной машине Windows 10/11 или в Windows Sandbox:
  1. `winget settings --enable LocalManifestFiles`;
  2. `winget install --manifest target/winget --silent`;
  3. обновление со старой версии;
  4. `winget uninstall`.

  Список сценариев — в [`winget-installer.md`](winget-installer.md). Имя и издатель записи в «Приложения и возможности» известны только после настоящей установки. Если WinGet не сопоставляет установленную версию, добавьте в `installer.yaml` `AppsAndFeaturesEntries` по этой записи.
- Имя пакета `arynyklas.OpenNCALayer` свободно: в `microsoft/winget-pkgs` нет каталога `manifests/a/arynyklas/OpenNCALayer/` и открытых PR с ним.
- Владелец проекта решил подавать пакет (первый fork и PR), дальше решает Microsoft.

## Как подать

1. Сделайте fork `microsoft/winget-pkgs` и ветку `arynyklas.OpenNCALayer-<версия>`.
2. Скопируйте три файла в `manifests/a/arynyklas/OpenNCALayer/<версия>/`.
3. Проверьте: `winget validate --manifest manifests/a/arynyklas/OpenNCALayer/<версия>`. Флаги `--force` и `--ignore-security-hash` не используйте.
4. Откройте PR с заголовком `New package: arynyklas.OpenNCALayer version <версия>`. Чек-лист шаблона отмечайте честно.
5. Отвечайте на замечания проверок Microsoft. Если файл релиза заменили после подачи, SHA-256 в манифесте перестанет совпадать: выпускайте новую версию.
6. После слияния и индексации (это занимает часы) проверьте в чистой виртуальной машине: `winget install --id arynyklas.OpenNCALayer --exact --source winget --silent`, обновление и удаление. Потом обновите упоминания WinGet в README и в [`docs/user/install.md`](../user/install.md).
