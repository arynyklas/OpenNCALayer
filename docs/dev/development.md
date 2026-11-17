# Разработка и сборка

Для тех, кто хочет собрать OpenNCALayer из исходников, запустить тесты и подготовить изменение. Сначала — как собрать и запустить, потом — что поставить для тестов и как их запускать.

Другие документы для разработчиков: выпуск версии — [`release.md`](release.md), встраивание SDK — [`sdk-overview.md`](sdk-overview.md) и [`sdk.md`](sdk.md).

## Сборка и запуск

Нужен `rustup`: нужная версия Rust записана в `rust-toolchain.toml` и ставится сама.

На Linux для окон нужны пакеты разработки fontconfig, xkbcommon, Wayland и GTK 3. В Debian и Ubuntu:

```sh
sudo apt-get install -y libfontconfig1-dev libxkbcommon-dev libwayland-dev libgtk-3-dev
```

Чтобы программа запускалась на Linux, нужны ещё:
- `libxkbcommon-x11-0`. Без неё окна подписи не открываются, а `openncalayer run` завершается с ошибкой. Пакет `libxkbcommon-dev` её не ставит;
- `xdg-desktop-portal` с бэкендом (например, `xdg-desktop-portal-gtk`) или `zenity`. Они нужны для кнопки «Обзор…». Без них диалог выбора файла не откроется (в журнале будет ошибка rfd), но путь к файлу ключа можно ввести руками.

Сборка:

```sh
cargo build --release -p openncalayer
```

Программа лежит в `target/release/openncalayer` (в Windows — `openncalayer.exe`).

### Первый запуск

Основной путь — мастер «Сертификат для браузера…» в меню значка (раздел [«Мастер TLS»](../user/desktop.md#мастер-tls)). То же из командной строки:

```sh
openncalayer tls init   # выпустить сертификат и напечатать, как установить CA
openncalayer run        # запустить сервер со значком; `openncalayer` без команды делает то же
```

1. Выпустите сертификат (мастером или `tls init`) и установите CA — кнопкой мастера или по напечатанной инструкции. Подробности по каждой ОС — в [`docs/user/tls.md`](../user/tls.md).
2. Запустите `openncalayer run` и откройте `https://127.0.0.1:13579/` (или `https://127.0.0.1:13579/openncalayer/selftest`). Страница должна открыться без предупреждения о сертификате.
3. На `https://127.0.0.1:13579/demo/` можно подписать текст или файл и скачать `.p7s`.
4. Проверьте подпись:

   ```sh
   oncl verify --profile cms --input signature.p7s --root <корневой сертификат НУЦ>
   ```

   - Демо-страница сохраняет `.p7s` в DER. `oncl verify` читает DER и BER; PEM — только с ключом `--pem` (один блок `CMS` или `PKCS7`, не больше 16 МиБ текста).
   - Корневые сертификаты сами не подставляются: передайте их через `--root`.
   - Подпись без вложенных данных: добавьте `--detached <файл данных>`.
   - `--offline` отключает проверку отзыва.
   - Проверяются подписи и метки времени, цепочки сертификатов подписанта и службы времени (по переданным корням), срок действия и отзыв. Команда печатает отчёт по каждой проверке; код выхода 0 — только если результат `Valid`.
   - Все ключи — в [`docs/user/cli.md`](../user/cli.md).

### Коды выхода `openncalayer run`

| Код | Что случилось |
|---|---|
| 2 | TLS не настроен |
| 3 | порт занят, например оригинальным NCALayer |
| 4 | OpenNCALayer с тем же каталогом данных уже запущен в этом сеансе |

Коды 2 и 3 бывают, только когда `wss` выключен и значка нет. Значка нет в таких случаях:
- запуск с `--no-tray`;
- значок не показался;
- значок пропал на первом проходе цикла окон (macOS);
- значок не принял StatusNotifierWatcher в течение минуты после запуска (Linux).

Если проблему к этому времени устранили (оригинал остановили из уведомления, сертификат сохранили), программа продолжает работать без значка.

Со значком всё иначе. При ненастроенном TLS или занятом порте программа не выходит: она работает для расширения, значок показывает проблему, а `wss` запускается, когда мастер сохранит сертификат или порт освободится. Программа, которую запустил пользователь или автозапуск, показывает уведомление и сама занимает освободившийся порт (проверка раз в 30 секунд).

С флагом `--allow-no-wss` программу запускает relay расширения. Любая ошибка запуска `wss` (коды 1, 2 и 3) тогда не останавливает её: она пишет предупреждение в журнал и работает только для расширения. Освободившийся порт такая программа сама не занимает: `wss` она запускает только после действия пользователя в значке или в мастере TLS (остановить оригинал, сохранить сертификат).

Оригинал и OpenNCALayer не могут одновременно работать по `wss`: обоим нужен порт 13579. Расширению порт не нужен.

### Где лежат данные

| ОС | Каталог данных |
|---|---|
| Windows | `%APPDATA%\OpenNCALayer` |
| macOS | `~/Library/Application Support/OpenNCALayer` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/openncalayer` |

Внутри:
- `tls/` — сертификаты;
- `logs/openncalayer.YYYY-MM-DD.log` — журналы, новый файл каждый день;
- `settings.json` — настройки (`locale`, `autostart`, `proxy`) и путь к последнему выбранному файлу ключа;
- `original-autostart.json` и `original-autostart/` — журнал и перенесённые записи автозапуска оригинала;
- `installation.json` — какая версия и откуда установлена (раздел [«Установка»](../user/install.md#установка)).

Переменная `ONCL_DATA_DIR` заменяет каталог данных. При разработке задавайте её (например, `ONCL_DATA_DIR=target/oncl-data`), чтобы не трогать свой настоящий профиль.

## Что нужно для тестов

Собрать проект можно без этого раздела, а вот `cargo test` без него упадёт. Часть тестов сверяет наш код с независимыми программами: OpenSSL, pyHanko, lxml и другими. Если нужной программы нет, тест **не пропускается, а падает**.

Что поставить:

| Что | Зачем | Как проверить |
|---|---|---|
| Rust | сборка и запуск тестов (ставится сам через `rustup`) | `cargo --version` |
| Системные библиотеки на Linux | окна Slint | см. «Сборка и запуск» |
| `openssl` в `PATH` | тесты `oncl-api` вызывают `openssl cms` | `openssl version` — нужен OpenSSL 3 |
| Отдельное окружение Python | независимые проверки подписей: pyHanko, lxml, cryptography, asn1crypto, gostcrypto | см. ниже |
| Тестовые данные NCANode | файлы для тестов | `cargo xtask fetch-fixtures` |

Docker, Node.js и браузеры для обычного `cargo test` не нужны. Они нужны только для отдельных проверок ниже.

### 1. OpenSSL

Нужен OpenSSL 3 с командами `cms` и `pkcs12 -legacy`. Так его ставит CI: на Linux — пакет `openssl`, на Windows — OpenSSL из Git for Windows, на macOS — Homebrew (`openssl@3`).

**Linux.** Обычно уже стоит. Если нет: `sudo apt-get install -y openssl`.

**macOS.** Системный `openssl` — это LibreSSL, он не подходит. Поставьте OpenSSL 3 и поставьте его папку первой в `PATH`:

```sh
brew install openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

**Windows.** Установите OpenSSL и добавьте его папку `bin` в `PATH`:

```powershell
winget install -e --id ShiningLight.OpenSSL.Light
```

Установщик кладёт OpenSSL в папку `OpenSSL-Win64` внутри `Program Files`. Добавьте в `PATH` папку `<папка OpenSSL>\bin` (Параметры → Система → О системе → Дополнительные параметры системы → Переменные среды) и **откройте новое окно терминала**. Проверка:

```powershell
openssl version
```

Тесты `oncl-cli` ищут OpenSSL ещё и в переменной `ONCL_OPENSSL` (полный путь к `openssl`), а в Windows — среди файлов Git for Windows. Тесты `oncl-api` берут только `openssl` из `PATH`, поэтому надёжнее всего положить его в `PATH`.

### 2. Отдельное окружение Python

Нужен Python 3.12 (так в CI). Не ставьте пакеты в системный Python: создайте для них своё виртуальное окружение. Папку `.venv-oracle` в корне репозитория не нужно коммитить. Список пакетов — в `xtask/assets/oracle/requirements.txt`.

**Linux и macOS:**

```sh
python3 -m venv .venv-oracle
.venv-oracle/bin/python -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/bin/python"
```

**Windows (PowerShell):**

```powershell
python -m venv .venv-oracle
.venv-oracle\Scripts\python.exe -m pip install --require-virtualenv -r xtask\assets\oracle\requirements.txt
$env:ONCL_PYHANKO_PYTHON = "$PWD\.venv-oracle\Scripts\python.exe"
```

**Windows (Git Bash):**

```sh
python -m venv .venv-oracle
.venv-oracle/Scripts/python.exe -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/Scripts/python.exe"
```

Вместо `python -m venv` можно взять `uv`: `uv venv .venv-oracle`, затем `uv pip install --python .venv-oracle/bin/python -r xtask/assets/oracle/requirements.txt` (в Windows — `.venv-oracle\Scripts\python.exe`).

Ключ `--require-virtualenv` — страховка: `pip` откажется ставить пакеты, если окружение не виртуальное.

Проверьте, что всё встало:

```sh
"$ONCL_PYHANKO_PYTHON" -c "import pyhanko, lxml, cryptography, asn1crypto, gostcrypto"
```

(В PowerShell: `& $env:ONCL_PYHANKO_PYTHON -c "import pyhanko, lxml, cryptography, asn1crypto, gostcrypto"`.)

Переменная `ONCL_PYHANKO_PYTHON` действует только в том терминале, где вы её задали. Чтобы она жила постоянно, задайте её в настройках среды: в Windows — `setx ONCL_PYHANKO_PYTHON <путь к python.exe окружения>` (подействует в новых терминалах), в Linux и macOS — строка `export` в `~/.profile` или `~/.zshrc`.

Тест не берёт «первый `python` из `PATH`»: на нём чаще всего нет `lxml`. Нужен именно интерпретатор окружения из `ONCL_PYHANKO_PYTHON`. Если переменная не задана или файла нет, тест падает с подсказкой про этот раздел.

### 3. Тестовые данные

```sh
cargo xtask fetch-fixtures
```

Команда скачивает тестовые файлы [NCANode](https://github.com/ncanode-kz/NCANode) с закреплённого коммита и проверяет их sha256 (в `target/fixtures/ncanode/`). Файлы не коммитятся. Если они уже на месте, повторный запуск ничего не качает.

## Разработка

### Тесты

```sh
cargo build --workspace
cargo xtask fetch-fixtures
cargo test --workspace --all-features
```

Перед этим выполните шаги из раздела «Что нужно для тестов». Полный набор тестов большой, поэтому в CI он разбит на три части. Для работы над одним крейтом хватает `cargo test -p <крейт>`.

Тестовые ключи в `fixtures/synthetic/` придуманные, пароль у них `Qwerty12`. Их можно использовать на демо-странице. По умолчанию демо отправляет `chain: []`, поэтому доступны и придуманные ключи, и тестовые ключи NCANode. Вариант «синтетический тестовый корень» передаёт `root-gost2015`: ключи других корней и промежуточного CA тогда недоступны.

#### Тесты с настоящими сервисами НУЦ

Тесты с пометкой `live_` ходят к настоящим сервисам НУЦ, поэтому по умолчанию не запускаются:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Это три теста:
- `live_test_tsa` — тестовая служба времени (TSP) НУЦ;
- `live_ocsp_nca_test_certificate` — тестовый OCSP НУЦ (нужен `cargo xtask fetch-fixtures`);
- `live_crl_nca_root_gost_2022` — CRL промышленного `crl.root.gov.kz`.

Они зависят от внешних сервисов, поэтому CI запускает их только по расписанию и вручную (`workflow_dispatch`, job `live`). Если такой тест упал один раз из-за сети, просто перезапустите его. Тестовый RSA-ответчик OCSP НУЦ на стандартные запросы (и от OpenSSL тоже) отвечает `malformedRequest`, поэтому живой OCSP проверяется на ГОСТ-сертификате.

#### Встроенные модули без маркеров

Тесты встроенных модулей (`cargo test -p oncl-builtin-tests`) идут и без маркеров. Обычно ядро заменяет длинные строки запроса маркерами. При `ONCL_TEST_NO_MARKERS=1` модуль читает строки как есть, и все тесты проходят так же. Тест `markers` сверяет ответы с маркерами и без них для каждой строки запросов покрытых методов, увеличенной до 20 000 байт (и для пачки документов длиннее 1 МиБ).

### Расширение браузера

```sh
node --test "extension/test/*.test.mjs"   # тесты расширения, Node 22 и новее
cargo xtask ext build                     # → target/extension/
```

Сквозная проверка расширения в Chrome for Testing, Firefox и Firefox ESR 115 (только Linux, браузеры и драйверы скачиваются в `target/browsers/`):

```sh
cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost
cargo xtask ext build
cargo xtask ext-e2e --download
```

- Без `--download` пути к браузерам берутся из переменных `ONCL_CHROME`, `ONCL_CHROMEDRIVER`, `ONCL_FIREFOX`, `ONCL_FIREFOX_ESR` и `ONCL_GECKODRIVER`.
- Один браузер: `--browser chromium|firefox|firefox-esr`.
- Firefox ESR 115 нужна системная библиотека `libdbus-glib-1-2`.
- Браузеры запускаются с одноразовыми профилями в `target/ext-e2e/`, хост регистрируется там же (`nm install --sandbox`).
- Фича `e2e-prompter` заменяет окна подписи сценарием из файла `ONCL_E2E_PROMPTER`. В обычных сборках её нет.
- Если шаг сценария не подходит к открывшемуся окну (например, ответ окна ключа на окно хранилища), вызов не падает: окно отменяется, в журнал пишется строка `… the window is cancelled`, страница получает обычный ответ на отмену, соединение остаётся открытым.
- Сценарий 8 удаляет расширение из открытой страницы. Он работает только в Firefox; в ESR 115 он проверяет ограничение этой версии (оно описано в [документации расширения](../user/browser-extension.md)).

### Проверка подписей в NCANode

Проверка наших подписей XMLDSig и CMS в NCANode (Kalkan). Только Linux, нужен Docker:

```sh
cargo xtask fetch-fixtures && cargo xtask interop-ncanode
```

Образ, порядок запуска и результат — в [`interop-ncanode.md`](interop-ncanode.md).

### Сборка для Windows 7

Только в Windows; нужен закреплённый nightly Rust:

```sh
rustup toolchain install nightly-2026-08-12 --profile minimal --component rust-src
cargo xtask win7 --arch all   # → target/win7/x64/, target/win7/x86/
```

`cargo xtask win7` собирает `openncalayer.exe` и `nmhost.exe` для 64- и 32-битной Windows 7 (статический CRT, поэтому VC++ redist не нужен). Рядом с ними кладёт две DLL-заглушки: в Windows 7 нет `combase.dll` и `api-ms-win-core-winrt-error-l1-1-0.dll`. Заглушки передают нужные вызовы в `ole32.dll` или ничего не делают. Windows 8 и новее эти копии не загружают.

Потом запускается проверка импортов (отдельно: `cargo xtask check-imports <exe>…`). Она не пропускает сборку, если:
- программа импортирует DLL или функцию из списка тех, которых нет в Windows 7. Это именно «чёрный список»: импорт из Windows 8+, которого в списке нет, проверка пропустит;
- импорт из `combase.dll` или `api-ms-win-core-winrt-error-l1-1-0.dll` не подкреплён одноимённой DLL рядом с exe, которая экспортирует ровно эту функцию;
- сами эти DLL другой разрядности, чем exe, или импортируют что-то кроме `kernel32.dll` и `ole32.dll`;
- `nmhost.exe` нуждается в этих DLL: он должен обходиться без них, потому что `nm install` копирует relay отдельно от программы.

В Windows после проверки `cargo xtask win7` запускает собранную программу: `--help`, `nm install` и `nm status` в песочнице, `tls init`, затем `run` до ответа на `GET /` по HTTPS. Данные при этом лежат во временном каталоге под `target/win7-smoke/`. В CI это обязательный job `win7` (x64 и x86 на Windows Server 2025). Проверок на настоящей Windows 7 в CI пока нет.

Ключ `--target-dir <каталог>` задаёт свой каталог сборки вместо `target/`. Job `win7` кэширует его целиком: обычный кэш cargo выбрасывает стандартную библиотеку `-Zbuild-std`, и без неё каждый раз пересобирается всё.

### Перед отправкой изменений

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo xtask licenses --check   # сторонние лицензии для окна «О программе» свежие
```

Если менялись `updates/` или `tuf/` (проверки индексов и репозитория TUF, разделы 4 и 7г в [`release.md`](release.md)):

```sh
cargo xtask index check updates/v1 --offline --base origin/main
cargo xtask tuf check --no-timestamp --base origin/main
```

### Клиент демо-страницы

`web/demo/vendor/ncalayer-client.js` — файл `package/ncalayer-client.js` из npm-пакета `ncalayer-js-client@1.6.1`, без изменений (MIT). Тест `demo_assets_served` сверяет sha256 файла, который отдаёт сервер. Лицензия клиента лежит рядом: `/demo/vendor/LICENSE`.

## Форки сторонних крейтов

Пять крейтов с crates.io нужны нам с небольшими изменениями. Их исходников в репозитории нет: они берутся по git из форков в аккаунте `arynyklas`. Версия форка закреплена полным коммитом (`rev`) в корневом `Cargo.toml`.

- `i-slint-backend-winit`, `velopack`, `streebog` и `hmac` подменяются в `[patch.crates-io]`.
- `hmac`, `streebog` и `multer` названы с тем же `git` и `rev` ещё и в `[workspace.dependencies]`, чтобы тот, кто подключает SDK или сервер вне этого workspace, получил тот же исходник.
- Каждое изменение — отдельный подписанный коммит в ветке форка `openncalayer/<крейт>-<версия>`. Ветка начинается с коммита апстрима, из которого опубликован этот крейт (он записан в `.cargo_vcs_info.json` пакета).
- Ветки не переписываются: новая правка — новый коммит и новый `rev`.

| Крейт | Форк и ветка | Откуда | Что изменено |
|---|---|---|---|
| `i-slint-backend-winit` 1.18.1 | [`arynyklas/slint`](https://github.com/arynyklas/slint), `openncalayer/i-slint-backend-winit-1.18.1` | [`slint-ui/slint`](https://github.com/slint-ui/slint), каталог `internal/backends/winit` | Функция `SystemParametersInfoForDpi` (есть с Windows 10 1607) не импортируется, а ищется через `GetProcAddress` (`windows_message_font_height` в `lib.rs`, её вызывает `bind_context`). Если её нет, вызывается `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)`, и высота шрифта пересчитывается из системного DPI в 96. Так сборка для Windows 7 не требует функции, которой там нет, а Windows 10/11 работают как раньше. Для этого включена фича `Win32_System_LibraryLoader` крейта `windows`. Ещё три коммита — упаковка: внутренние крейты Slint и `vtable` указаны по версии, а не по пути (иначе git-зависимость принесла бы вторую, несовместимую по типам копию), а тексты лицензий в `LICENSES/` — обычные файлы, а не symlink. |
| `velopack` 1.3.39-g8d2844f | [`arynyklas/velopack`](https://github.com/arynyklas/velopack), `openncalayer/velopack-1.3.39-g8d2844f` | [`velopack/velopack`](https://github.com/velopack/velopack), каталог `src/lib-rust` | В `UpdateSource` добавлен метод `verify_full_package` (по умолчанию — проверка размера и контрольной суммы, как у самого Velopack). `download_updates` проверяет им полный пакет, который уже лежит на диске (не прошедший проверку удаляется и скачивается заново), и пакет, собранный из дельты, — до переименования и до извлечения `Squirrel.exe` (Update.exe). Не прошедший проверку заменяется скачиванием полного пакета. Наш `IndexSource` принимает файл, если он совпадает с полным пакетом из подписанного индекса по sha256 и размеру или содержит те же файлы (`contents_sha256` индекса). Ещё два коммита — упаковка: версия крейта (в репозитории `0.0.0-local`, релиз подставляет опубликованную) и файл `LICENSE` в каталоге крейта (в пакете crates.io его нет). |
| `streebog` 0.11.0 | [`arynyklas/hashes`](https://github.com/arynyklas/hashes), `openncalayer/streebog-0.11.0` | [`RustCrypto/hashes`](https://github.com/RustCrypto/hashes), крейт `streebog` | Фича `secret-input`: варианты `Streebog256Secret` и `Streebog512Secret`. У них один рабочий буфер, который очищается, выбор слов таблицы идёт без ветвлений, а состояние не сериализуется. Обычное хеширование публичных документов не меняется. |
| `hmac` 0.13.0 | [`arynyklas/MACs`](https://github.com/arynyklas/MACs), `openncalayer/hmac-0.13.0` | [`RustCrypto/MACs`](https://github.com/RustCrypto/MACs), крейт `hmac` | Фича `secret-input`: тип `HmacSecret` очищает нормализованный ключ, блоки ipad/opad и внутренний дайджест. Обычный `Hmac` не меняется. |
| `multer` 3.1.0 | [`arynyklas/multer`](https://github.com/arynyklas/multer), `openncalayer/multer-3.1.0` | [`rwf2/multer`](https://github.com/rwf2/multer) | `Constraints::framing_observer` — необязательный наблюдатель за служебными байтами multipart (границы, заголовки частей, отступы), разбор он не меняет. Плюс `cfg(nightly)` для check-cfg и `u64::MAX`, и проверенное сложение счётчика размера потока (`StreamSizeExceeded` вместо переполнения). |

Лицензии:
- `streebog` и `hmac` — MIT или Apache-2.0;
- `multer` и `velopack` — MIT;
- `i-slint-backend-winit` — Slint Royalty-free 2.0. Она разрешает изменять программу и распространять изменённую копию в составе приложения (разделы 1–2); уведомления о лицензии в файлах сохранены.

Полные тексты попадают в `THIRD-PARTY.txt` вместе с остальными зависимостями, подробности — в `NOTICE`.

Тест `xtask/tests/forks.rs` падает, если:
- патч остался неиспользованным (`Cargo.lock` снова берёт пакет из crates.io);
- `rev` в разных секциях разошлись;
- версия `i-slint-backend-winit` перестала совпадать с версией Slint.

`cargo deny check` разрешает только git-источники этих форков (`[sources] allow-git` в `deny.toml`).

Как обновить крейт:
1. Перенесите ветку форка на новый тег апстрима (`git rebase`).
2. Запушьте её под именем новой версии.
3. Поменяйте `rev` (и версию, если она закреплена, как у `velopack`).
4. Обновите `Cargo.lock` и этот раздел.

## Сайт проекта: локальная сборка

Собрать сайт: `cargo xtask registry build`. Zola 0.23.6 скачивается в `target/tools/` и проверяется по sha256. Результат — `target/site/public`; ссылки и правила страниц проверяются сразу после сборки. Отдельная проверка: `cargo xtask registry check <каталог>`.

Посмотреть сайт в браузере:

```sh
target/tools/zola-v0.23.6/zola --root target/site/src serve
```

Тесты сборки сайта с Zola называются `zola_…` и по умолчанию не запускаются:

```sh
cargo test -p xtask --test registry_site -- --ignored zola_
```

В CI их запускает job `site`.

Исходники сайта — в `site/` (настройки, шаблоны, стили, тексты). Страницы портов и `data/site.json` генерируются в `target/site/src` и не коммитятся.
