# WinGet: манифест и подача

Как получить манифест опубликованного релиза и подать его в `microsoft/winget-pkgs`. Команда `winget install --id arynyklas.OpenNCALayer --exact` работает только после слияния пакета (шаг 6 подачи).

## Установщик в манифесте

WinGet запускает не обычный `…-setup.exe`, а `openncalayer-<версия>-win-<x64|x86>-winget-setup.exe` (только Windows 10 1809+; Windows 7 в WinGet не заявлен). Это маленькая обёртка `oncl-winget-setup` с неизменённым Velopack `Setup.exe` внутри ([`winget-installer.md`](winget-installer.md)). Она нужна, потому что закреплённый Velopack `Setup.exe` (`8d2844f324a69bd848719ef465b1ae12c5060524`, `src/bins/src/commands/install.rs`) при переустановке безусловно завершает установленную программу (`force_stop_package`, в том числе посреди подписи), а при невыполненных prerequisites возвращает `Ok(())` и выходит с кодом 0, ничего не поставив; оба действия происходят в самом `Setup.exe` до любых хуков приложения и не настраиваются параметрами `vpk pack`. Обёртка просит запущенную программу «замереть» через `oncl_ipc::maintenance`, проверяет результат установки и возвращает честный код возврата.

## Манифест

```sh
cargo xtask winget manifest --version 0.2.0
```

Версия — как в теге без `v`. Команда скачивает `SHA256SUMS` релиза `v<версия>` (или берёт файл из `--sums <путь>`) и пишет в `target/winget` (`--out`) три файла схемы 1.12.0: `arynyklas.OpenNCALayer.yaml`, `….locale.en-US.yaml`, `….installer.yaml`. В `installer.yaml` два установщика, `x64` и `x86`: URL — ассеты этого релиза `https://github.com/arynyklas/OpenNCALayer/releases/download/v<версия>/…`, SHA-256 — из `SHA256SUMS`. Установщик принимает только `--silent` (интерактивного режима нет), код 4 («занято: идёт подпись») описан как `packageInUse`, а не успех, `Scope: user`, повышение запрещено. Ничего не сохраняется в репозитории.

Проверка: `winget validate target/winget` (проверяет схему, не установку).

## Что нужно до подачи

- Опубликованный релиз **без суффикса** (`0.x.y`, не `-alpha.N`): в WinGet подаются только stable-версии.
- Оба `winget-setup.exe` подписаны Authenticode: настроен SignPath, в артефакте разрешён `*-winget-setup.exe` ([`winget-installer.md`](winget-installer.md), «Шаг оператора»). Без подписи манифест не подавать.
- Установка проверена в чистой Windows 10/11 ВМ или Sandbox (`winget settings --enable LocalManifestFiles`, затем `winget install --manifest target/winget --silent`, upgrade со старой версии, `winget uninstall`). Список сценариев — в [`winget-installer.md`](winget-installer.md). Имя и издатель записи Apps & Features известны только по настоящей установке: если WinGet не сопоставляет установленную версию, добавьте в `installer.yaml` `AppsAndFeaturesEntries` по этой записи.
- `PackageIdentifier` `arynyklas.OpenNCALayer` свободен: в `microsoft/winget-pkgs` нет каталога `manifests/a/arynyklas/OpenNCALayer/` и открытых PR с ним.
- Решение владельца проекта на первый fork и PR, затем решение Microsoft.

## Подача

1. Сделайте fork `microsoft/winget-pkgs` и ветку `arynyklas.OpenNCALayer-<версия>`.
2. Скопируйте три файла в `manifests/a/arynyklas/OpenNCALayer/<версия>/`.
3. `winget validate --manifest manifests/a/arynyklas/OpenNCALayer/<версия>`; флаги `--force` и `--ignore-security-hash` не использовать.
4. PR с заголовком `New package: arynyklas.OpenNCALayer version <версия>`; чек-лист шаблона отмечайте честно.
5. Ответьте на замечания проверок Microsoft. Если ассет релиза заменён после подачи, SHA-256 манифеста перестанет совпадать: выпускайте новую версию.
6. После слияния и индексации (часы) проверьте в чистой ВМ `winget install --id arynyklas.OpenNCALayer --exact --source winget --silent`, upgrade и uninstall; затем обновите упоминания WinGet в README и [`docs/user/install.md`](../user/install.md).
