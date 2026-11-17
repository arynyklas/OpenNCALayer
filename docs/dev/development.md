# Разработка и сборка

Как собрать OpenNCALayer, запустить тесты и проверить изменение перед PR.

## Коротко: от клона до зелёных тестов

1. Поставьте `rustup`, OpenSSL 3 и Python 3.12 или новее (в CI стоит 3.12). На Linux до `cargo test --workspace` нужны ещё пакеты разработки для окон из раздела [«Сборка и запуск»](#сборка-и-запуск): `libfontconfig1-dev libxkbcommon-dev libwayland-dev libgtk-3-dev`. Подробности в разделе [«Что нужно для тестов»](#что-нужно-для-тестов).
2. Создайте для тестов отдельное окружение Python и укажите путь к нему:
   ```sh
   python3 -m venv .venv-oracle
   .venv-oracle/bin/python -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
   export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/bin/python"
   ```
   В Windows интерпретатор лежит в `.venv-oracle\Scripts\python.exe`.
3. Скачайте тестовые данные: `cargo xtask fetch-fixtures`.
4. Запустите тесты: `cargo test --workspace`.
5. Перед PR выполните `cargo xtask privacy` и проверки из раздела [«Перед отправкой изменений»](#перед-отправкой-изменений).

Если какой-то шаг не сработал, напишите в [Issues](https://github.com/arynyklas/OpenNCALayer/issues): значит, ошибка в этой инструкции.

Другие документы для разработчиков: выпуск версии описан в [`release.md`](release.md), встраивание SDK в [`sdk-overview.md`](sdk-overview.md) и [`sdk.md`](sdk.md).

## Сборка и запуск

Нужен `rustup`. Версия Rust записана в `rust-toolchain.toml` и ставится автоматически.

На Linux для окон нужны пакеты разработки fontconfig, xkbcommon, Wayland и GTK 3. В Debian и Ubuntu:

```sh
sudo apt-get install -y libfontconfig1-dev libxkbcommon-dev libwayland-dev libgtk-3-dev
```

Для запуска программы на Linux нужны ещё два компонента:
- `libxkbcommon-x11-0`. Без неё окна подписи не открываются, а `openncalayer run` завершается с ошибкой. Пакет `libxkbcommon-dev` её не ставит.
- `xdg-desktop-portal` с бэкендом (например, `xdg-desktop-portal-gtk`) или `zenity`, для кнопки «Обзор…». Без них диалог выбора файла не откроется (в журнале будет ошибка rfd), но путь к файлу ключа можно ввести вручную.

Сборка:

```sh
cargo build --release -p openncalayer
```

Программа появится в `target/release/openncalayer` (в Windows `openncalayer.exe`).

### Первый запуск

Проще всего настроить сертификат мастером «Сертификат для браузера…» в меню значка (раздел [«Мастер TLS»](../user/desktop.md#мастер-tls)). Из командной строки то же самое:

```sh
openncalayer tls init   # выпустить сертификат и напечатать, как установить CA
openncalayer run        # запустить сервер со значком; `openncalayer` без команды делает то же
```

1. Выпустите сертификат (мастером или `tls init`) и установите CA кнопкой мастера или по напечатанной инструкции. Подробности для каждой ОС в [`docs/user/tls.md`](../user/tls.md).
2. Запустите `openncalayer run` и откройте `https://127.0.0.1:13579/` (или `https://127.0.0.1:13579/openncalayer/selftest`). Страница должна открыться без предупреждения о сертификате.
3. На `https://127.0.0.1:13579/demo/` можно подписать текст или файл и скачать `.p7s`.
4. Проверьте подпись:

   ```sh
   oncl verify --profile cms --input signature.p7s --root <корневой сертификат НУЦ>
   ```

   - Демо-страница сохраняет `.p7s` в DER. `oncl verify` читает DER и BER, а PEM только с ключом `--pem` (один блок `CMS` или `PKCS7`, не больше 16 МиБ текста).
   - Корневые сертификаты автоматически не подставляются, их нужно передать через `--root`.
   - Для подписи без вложенных данных добавьте `--detached <файл данных>`.
   - `--offline` отключает проверку отзыва.
   - Команда проверяет подписи и метки времени, цепочки сертификатов подписанта и службы времени (по переданным корням), срок действия и отзыв, и печатает отчёт по каждой проверке. Код выхода 0 бывает, только если результат `Valid`.
   - Все ключи команды перечислены в [`docs/user/cli.md`](../user/cli.md).

### Коды выхода `openncalayer run`

| Код | Что случилось |
|---|---|
| 2 | TLS не настроен |
| 3 | порт занят, например оригинальным NCALayer |
| 4 | OpenNCALayer с тем же каталогом данных уже запущен в этом сеансе |

Коды 2 и 3 возможны, только когда `wss` выключен и значка нет. Значка нет в таких случаях:
- запуск с `--no-tray`;
- значок не удалось показать;
- значок пропал на первом проходе цикла окон (macOS);
- StatusNotifierWatcher не принял значок в течение минуты после запуска (Linux).

Если к этому моменту проблему устранили (оригинал остановили из уведомления, сертификат сохранили), программа продолжает работать без значка.

Если значок есть, программа при ненастроенном TLS или занятом порте не завершается. Она обслуживает расширение, значок показывает проблему, а `wss` запускается, когда мастер сохранит сертификат или порт освободится. Программа, которую запустил пользователь или автозапуск, показывает уведомление и сама занимает освободившийся порт (проверяет раз в 30 секунд).

С флагом `--allow-no-wss` программу запускает relay расширения. В этом режиме ошибка запуска `wss` (коды 1, 2 и 3) не останавливает программу: она пишет предупреждение в журнал и работает только для расширения. Освободившийся порт она сама не занимает и запускает `wss` только после действия пользователя в значке или мастере TLS (остановить оригинал, сохранить сертификат).

Оригинал и OpenNCALayer не могут одновременно работать по `wss`, потому что обоим нужен порт 13579. Расширению порт не нужен.

### Где лежат данные

| ОС | Каталог данных |
|---|---|
| Windows | `%APPDATA%\OpenNCALayer` |
| macOS | `~/Library/Application Support/OpenNCALayer` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/openncalayer` |

Внутри:
- `tls/`: сертификаты;
- `logs/openncalayer.YYYY-MM-DD.log`: журналы, новый файл каждый день;
- `settings.json`: настройки (`locale`, `autostart`, `proxy`) и путь к последнему выбранному файлу ключа;
- `original-autostart.json` и `original-autostart/`: журнал и перенесённые записи автозапуска оригинала;
- `installation.json`: какая версия и откуда установлена (раздел [«Установка»](../user/install.md#установка)).

Переменная `ONCL_DATA_DIR` задаёт другой каталог данных. При разработке укажите её (например, `ONCL_DATA_DIR=target/oncl-data`), чтобы не трогать свой рабочий профиль.

## Что нужно для тестов

Для сборки этот раздел не нужен, а `cargo test` без него упадёт. Часть тестов сверяет результат нашего кода с независимыми программами: OpenSSL, pyHanko, lxml и другими. Если нужной программы нет, тест падает, а не пропускается.

Что поставить:

| Что | Зачем | Как проверить |
|---|---|---|
| Rust | сборка и запуск тестов (ставится сам через `rustup`) | `cargo --version` |
| Системные библиотеки на Linux | окна Slint | см. «Сборка и запуск» |
| OpenSSL 3 | многие тесты проверяют наши подписи командой `openssl` | `openssl version`. Ищется в `ONCL_OPENSSL`, затем в `PATH`; в Windows ещё `openssl.exe` из Git for Windows |
| `git` в `PATH` | тесты `xtask` и сборки встроенных модулей | `git --version` |
| JDK, `keytool` в `PATH` | тест JKS в `oncl-cli` | `keytool -help` |
| `python` в `PATH` | вспомогательные скрипты тестов (без сторонних пакетов) | `python --version` |
| `certutil` из NSS (только Linux; пакет `libnss3-tools` или `nss-tools`) | тесты записи сертификата в базы браузеров в `oncl-trust` | `certutil -H` |
| Отдельное окружение Python | независимая проверка подписей: pyHanko, lxml, cryptography, asn1crypto, gostcrypto | см. ниже |
| Тестовые данные NCANode | файлы для тестов | `cargo xtask fetch-fixtures` |

Docker, Node.js и браузеры для обычного `cargo test` не нужны, они используются только в отдельных проверках ниже.

### 1. OpenSSL

Нужен OpenSSL 3 с командами `cms` и `pkcs12 -legacy`. В CI он берётся так: на Linux пакет `openssl`, на Windows OpenSSL из Git for Windows, на macOS Homebrew (`openssl@3`).

Linux. Обычно OpenSSL уже установлен. Если нет: `sudo apt-get install -y openssl`.

macOS. Системный `openssl` на самом деле LibreSSL и не подходит. Поставьте OpenSSL 3 и поместите его каталог первым в `PATH`:

```sh
brew install openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

Windows. Установите OpenSSL и добавьте его каталог `bin` в `PATH`:

```powershell
winget install -e --id ShiningLight.OpenSSL.Light
```

Установщик кладёт OpenSSL в каталог `OpenSSL-Win64` внутри `Program Files`. Добавьте `<каталог OpenSSL>\bin` в `PATH` (Параметры, Система, О системе, Дополнительные параметры системы, Переменные среды) и откройте новое окно терминала. Проверка:

```powershell
openssl version
```

Тесты `oncl-cli` ищут OpenSSL ещё и в переменной `ONCL_OPENSSL` (полный путь к `openssl`), а в Windows также среди файлов Git for Windows. Тесты `oncl-api` берут только `openssl` из `PATH`, поэтому надёжнее всего добавить его в `PATH`.

### 2. Отдельное окружение Python

Нужен Python 3.12 или новее (в CI стоит 3.12). Пакеты не ставьте в системный Python. Создайте для них venv, то есть изолированное окружение Python со своим интерпретатором и своим набором пакетов. Каталог `.venv-oracle` в корне репозитория коммитить не нужно. Список пакетов лежит в `xtask/assets/oracle/requirements.txt`.

Linux и macOS:

```sh
python3 -m venv .venv-oracle
.venv-oracle/bin/python -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/bin/python"
```

Windows (PowerShell):

```powershell
python -m venv .venv-oracle
.venv-oracle\Scripts\python.exe -m pip install --require-virtualenv -r xtask\assets\oracle\requirements.txt
$env:ONCL_PYHANKO_PYTHON = "$PWD\.venv-oracle\Scripts\python.exe"
```

Windows (Git Bash):

```sh
python -m venv .venv-oracle
.venv-oracle/Scripts/python.exe -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/Scripts/python.exe"
```

Вместо `python -m venv` можно использовать `uv`: `uv venv .venv-oracle`, затем `uv pip install --python .venv-oracle/bin/python -r xtask/assets/oracle/requirements.txt` (в Windows путь `.venv-oracle\Scripts\python.exe`).

С ключом `--require-virtualenv` `pip` откажется ставить пакеты, если случайно запущен не из окружения.

Проверьте, что пакеты встали:

```sh
"$ONCL_PYHANKO_PYTHON" -c "import pyhanko, lxml, cryptography, asn1crypto, gostcrypto"
```

(В PowerShell: `& $env:ONCL_PYHANKO_PYTHON -c "import pyhanko, lxml, cryptography, asn1crypto, gostcrypto"`.)

Переменная `ONCL_PYHANKO_PYTHON` действует только в том терминале, где её задали. Чтобы она сохранялась, задайте её в настройках среды: в Windows командой `setx ONCL_PYHANKO_PYTHON <путь к python.exe окружения>` (подействует в новых терминалах), в Linux и macOS строкой `export` в `~/.profile` или `~/.zshrc`.

Тесты не берут первый попавшийся `python` из `PATH`, потому что в нём обычно нет `lxml`. Им нужен интерпретатор окружения из `ONCL_PYHANKO_PYTHON`. Если переменная не задана или файла нет, тест падает и ссылается на этот раздел.

### 3. Тестовые данные

```sh
cargo xtask fetch-fixtures
```

Команда скачивает тестовые файлы [NCANode](https://github.com/ncanode-kz/NCANode) с закреплённого коммита в `target/fixtures/ncanode/` и проверяет их sha256. Файлы в репозиторий не попадают. Если они уже скачаны, повторный запуск ничего не загружает.

## Разработка

### Тесты

```sh
cargo build --workspace
cargo xtask fetch-fixtures
cargo test --workspace --all-features
```

Сначала выполните шаги из раздела «Что нужно для тестов». Полный набор тестов большой, и в CI он разбит на три части. Когда работаете над одним крейтом, достаточно `cargo test -p <крейт>`.

Тестовые ключи в `fixtures/synthetic/` синтетические, пароль у них `Qwerty12`. Их можно использовать на демо-странице. По умолчанию демо отправляет `chain: []`, и тогда подходят и синтетические ключи, и тестовые ключи NCANode. Вариант «синтетический тестовый корень» передаёт `root-gost2015`, и ключи других корней и промежуточного CA становятся недоступны.

#### Тесты с настоящими сервисами НУЦ

Тесты с префиксом `live_` обращаются к настоящим сервисам НУЦ, поэтому по умолчанию не запускаются:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Их три:
- `live_test_tsa`: тестовая служба времени (TSP) НУЦ;
- `live_ocsp_nca_test_certificate`: тестовый OCSP НУЦ (нужен `cargo xtask fetch-fixtures`);
- `live_crl_nca_root_gost_2022`: CRL промышленного `crl.root.gov.kz`.

Они зависят от внешних сервисов, поэтому в CI запускаются только по расписанию и вручную (`workflow_dispatch`, job `live`). Если такой тест один раз упал из-за сети, перезапустите его. Тестовый RSA-ответчик OCSP НУЦ отвечает `malformedRequest` на стандартные запросы, в том числе от OpenSSL, поэтому OCSP проверяется на ГОСТ-сертификате.

#### Встроенные модули без маркеров

Тесты встроенных модулей (`cargo test -p oncl-builtin-tests`) проходят и без маркеров. Обычно ядро заменяет длинные строки запроса маркерами. При `ONCL_TEST_NO_MARKERS=1` модуль читает строки как есть, и все тесты проходят так же. Тест `markers` сравнивает ответы с маркерами и без них для каждой строки запросов покрытых методов, увеличенной до 20 000 байт (и для пачки документов длиннее 1 МиБ).

### Расширение браузера

```sh
node --test "extension/test/*.test.mjs"   # тесты расширения, Node 22 и новее
cargo xtask ext build                     # → target/extension/
```

Сквозная проверка расширения в Chrome for Testing, Firefox и Firefox ESR 115 работает только на Linux. Браузеры и драйверы скачиваются в `target/browsers/`:

```sh
cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost
cargo xtask ext build
cargo xtask ext-e2e --download
```

- Без `--download` пути к браузерам берутся из переменных `ONCL_CHROME`, `ONCL_CHROMEDRIVER`, `ONCL_FIREFOX`, `ONCL_FIREFOX_ESR` и `ONCL_GECKODRIVER`.
- Один браузер выбирается ключом `--browser chromium|firefox|firefox-esr`.
- Для Firefox ESR 115 нужна системная библиотека `libdbus-glib-1-2`.
- Браузеры запускаются с одноразовыми профилями в `target/ext-e2e/`, хост регистрируется там же (`nm install --sandbox`).
- Фича `e2e-prompter` заменяет окна подписи сценарием из файла `ONCL_E2E_PROMPTER`. В обычные сборки она не входит.
- Если шаг сценария не подходит к открывшемуся окну (например, ответ для окна ключа пришёл окну хранилища), вызов не падает. Окно отменяется, в журнал пишется строка `… the window is cancelled`, страница получает обычный ответ об отмене, и соединение остаётся открытым.
- Сценарий 8 удаляет расширение при открытой странице. Он работает только в Firefox, а в ESR 115 проверяет ограничение этой версии, описанное в [документации расширения](../user/browser-extension.md).

### Проверка подписей в NCANode

Проверка наших подписей XMLDSig и CMS в NCANode (Kalkan). Работает только на Linux, нужен Docker:

```sh
cargo xtask fetch-fixtures && cargo xtask interop-ncanode
```

Образ, порядок запуска и результат описаны в [`interop-ncanode.md`](interop-ncanode.md).

### Сборка для Windows 7

Собирается только в Windows, нужен закреплённый nightly Rust:

```sh
rustup toolchain install nightly-2026-08-12 --profile minimal --component rust-src
cargo xtask win7 --arch all   # → target/win7/x64/, target/win7/x86/
```

`cargo xtask win7` собирает `openncalayer.exe` и `nmhost.exe` для 64- и 32-битной Windows 7 со статическим CRT, поэтому VC++ redist не нужен. Рядом кладутся две DLL-заглушки, потому что в Windows 7 нет `combase.dll` и `api-ms-win-core-winrt-error-l1-1-0.dll`. Заглушки передают нужные вызовы в `ole32.dll` или ничего не делают. Windows 8 и новее эти копии не загружают.

Затем запускается проверка импортов (отдельно: `cargo xtask check-imports <exe>…`). Сборка не проходит, если:
- программа импортирует DLL или функцию из списка отсутствующих в Windows 7. Это чёрный список: импорт из Windows 8+, которого в списке нет, проверка пропустит;
- импорт из `combase.dll` или `api-ms-win-core-winrt-error-l1-1-0.dll` не подкреплён одноимённой DLL рядом с exe, которая экспортирует именно эту функцию;
- сами эти DLL другой разрядности, чем exe, или импортируют что-то кроме `kernel32.dll` и `ole32.dll`;
- `nmhost.exe` зависит от этих DLL. Он должен обходиться без них, потому что `nm install` копирует relay отдельно от программы.

После проверки в Windows `cargo xtask win7` запускает собранную программу: `--help`, `nm install` и `nm status` в песочнице, `tls init`, затем `run` до ответа на `GET /` по HTTPS. Данные при этом лежат во временном каталоге в `target/win7-smoke/`. В CI это обязательный job `win7` (x64 и x86 на Windows Server 2025). На настоящей Windows 7 CI ничего не проверяет.

Ключ `--target-dir <каталог>` задаёт каталог сборки вместо `target/`. Job `win7` кэширует его целиком: обычный кэш cargo выбрасывает стандартную библиотеку `-Zbuild-std`, и без неё всё пересобирается заново.

### Перед отправкой изменений

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo xtask licenses --check   # сторонние лицензии для окна «О программе» свежие
```

Если менялись `updates/` или `tuf/` (проверки индексов и репозитория TUF описаны в разделах 3 и 10 [`release.md`](release.md)):

```sh
cargo xtask index check updates/v1 --offline --base origin/main
cargo xtask tuf check --no-timestamp --base origin/main
```

### Клиент демо-страницы

`web/demo/vendor/ncalayer-client.js` взят без изменений из npm-пакета `ncalayer-js-client@1.6.1` (файл `package/ncalayer-client.js`, лицензия MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). Тест `demo_assets_served` сверяет sha256 файла, который отдаёт сервер. Лицензия клиента лежит рядом: `/demo/vendor/LICENSE`.

## Форки сторонних крейтов

Пять крейтов с crates.io нужны нам с небольшими изменениями. Их исходников в репозитории нет: они берутся по git из форков в аккаунте `arynyklas`. Версия форка закреплена полным коммитом (`rev`) в корневом `Cargo.toml`.

- `i-slint-backend-winit`, `velopack`, `streebog` и `hmac` подменяются в `[patch.crates-io]`.
- `hmac`, `streebog` и `multer` указаны с тем же `git` и `rev` ещё и в `[workspace.dependencies]`, чтобы проект, который подключает SDK или сервер вне этого workspace, получил тот же исходник.
- Каждое изменение лежит отдельным подписанным коммитом в ветке форка `openncalayer/<крейт>-<версия>`. Ветка начинается с коммита апстрима, из которого опубликован крейт (он записан в `.cargo_vcs_info.json` пакета).
- Ветки не переписываются. Новая правка означает новый коммит и новый `rev`.

| Крейт | Форк и ветка | Откуда | Что изменено |
|---|---|---|---|
| `i-slint-backend-winit` 1.18.1 | [`arynyklas/slint`](https://github.com/arynyklas/slint), `openncalayer/i-slint-backend-winit-1.18.1` | [`slint-ui/slint`](https://github.com/slint-ui/slint), каталог `internal/backends/winit` | Функция `SystemParametersInfoForDpi` (есть с Windows 10 1607) не импортируется, а ищется через `GetProcAddress` (`windows_message_font_height` в `lib.rs`, её вызывает `bind_context`). Если функции нет, вызывается `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)`, и высота шрифта пересчитывается из системного DPI в 96. Так сборке для Windows 7 не нужна отсутствующая там функция, а на Windows 10/11 поведение прежнее. Для этого включена фича `Win32_System_LibraryLoader` крейта `windows`. Ещё три коммита касаются упаковки: внутренние крейты Slint и `vtable` указаны по версии, а не по пути (иначе git-зависимость принесла бы вторую копию с несовместимыми типами), а тексты лицензий в `LICENSES/` сделаны обычными файлами вместо symlink. |
| `velopack` 1.3.39-g8d2844f | [`arynyklas/velopack`](https://github.com/arynyklas/velopack), `openncalayer/velopack-1.3.39-g8d2844f` | [`velopack/velopack`](https://github.com/velopack/velopack), каталог `src/lib-rust` | В `UpdateSource` добавлен метод `verify_full_package` (по умолчанию проверяет размер и контрольную сумму, как сам Velopack). `download_updates` проверяет им полный пакет, уже лежащий на диске (непрошедший удаляется и скачивается заново), и пакет, собранный из дельты, до переименования и до извлечения `Squirrel.exe` (Update.exe). Непрошедший пакет заменяется скачанным полным. Наш `IndexSource` принимает файл, если он совпадает с полным пакетом из подписанного индекса по sha256 и размеру или содержит те же файлы (`contents_sha256` индекса). Ещё два коммита касаются упаковки: версия крейта (в репозитории `0.0.0-local`, релиз подставляет опубликованную) и файл `LICENSE` в каталоге крейта (в пакете crates.io его нет). |
| `streebog` 0.11.0 | [`arynyklas/hashes`](https://github.com/arynyklas/hashes), `openncalayer/streebog-0.11.0` | [`RustCrypto/hashes`](https://github.com/RustCrypto/hashes), крейт `streebog` | Фича `secret-input`: варианты `Streebog256Secret` и `Streebog512Secret`. У них один рабочий буфер, который очищается, слова таблицы выбираются без ветвлений, а состояние не сериализуется. Обычное хеширование публичных документов не меняется. |
| `hmac` 0.13.0 | [`arynyklas/MACs`](https://github.com/arynyklas/MACs), `openncalayer/hmac-0.13.0` | [`RustCrypto/MACs`](https://github.com/RustCrypto/MACs), крейт `hmac` | Фича `secret-input`: тип `HmacSecret` очищает нормализованный ключ, блоки ipad/opad и внутренний дайджест. Обычный `Hmac` не меняется. |
| `multer` 3.1.0 | [`arynyklas/multer`](https://github.com/arynyklas/multer), `openncalayer/multer-3.1.0` | [`rwf2/multer`](https://github.com/rwf2/multer) | `Constraints::framing_observer`: необязательный наблюдатель за служебными байтами multipart (границы, заголовки частей, отступы), разбор он не меняет. Также `cfg(nightly)` для check-cfg и `u64::MAX` и проверенное сложение счётчика размера потока (`StreamSizeExceeded` вместо переполнения). |

Лицензии:
- `streebog` и `hmac`: MIT или Apache-2.0;
- `multer` и `velopack`: MIT;
- `i-slint-backend-winit`: Slint Royalty-free 2.0. Она разрешает изменять программу и распространять изменённую копию в составе приложения (разделы 1 и 2), уведомления о лицензии в файлах сохранены.

Полные тексты попадают в `THIRD-PARTY.txt` вместе с остальными зависимостями, подробности в `NOTICE`.

Тест `xtask/tests/forks.rs` падает, если:
- патч не используется (`Cargo.lock` снова берёт пакет с crates.io);
- `rev` в разных секциях не совпадают;
- версия `i-slint-backend-winit` разошлась с версией Slint.

`cargo deny check` разрешает только git-источники этих форков (`[sources] allow-git` в `deny.toml`).

Как обновить крейт:
1. Перенесите ветку форка на новый тег апстрима (`git rebase`).
2. Запушьте её под именем новой версии.
3. Поменяйте `rev` (и версию, если она закреплена, как у `velopack`).
4. Обновите `Cargo.lock` и этот раздел.

## Сайт проекта: локальная сборка

Сайт собирается командой `cargo xtask registry build`. Zola 0.23.6 скачивается в `target/tools/` и проверяется по sha256. Результат появляется в `target/site/public`, ссылки и правила страниц проверяются сразу после сборки. Отдельно проверить готовый каталог можно командой `cargo xtask registry check <каталог>`.

Посмотреть сайт в браузере:

```sh
target/tools/zola-v0.23.6/zola --root target/site/src serve
```

Тесты сборки сайта с Zola называются `zola_…` и по умолчанию не запускаются:

```sh
cargo test -p xtask --test registry_site -- --ignored zola_
```

В CI их запускает job `site`.

Исходники сайта (настройки, шаблоны, стили, тексты) лежат в `site/`. Страницы портов и `data/site.json` генерируются в `target/site/src` и не коммитятся.
