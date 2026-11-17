# Командная строка `oncl`

`oncl` — программа для подписи и проверки файлов из терминала и скриптов. Она нужна тем, кто хочет подписывать без окон и браузера: администраторам, разработчикам, автоматическим сборкам. Здесь — как её получить, основные команды и справочник по флагам и кодам выхода.

Как это работает:
- по умолчанию `oncl` работает целиком на вашем компьютере. Она не запускает настольную программу, HTTP-сервер или браузер;
- с флагом `--endpoint` она, наоборот, отправляет работу на сервер `oncl-server` ([«Удалённый режим»](#удалённый-режим---endpoint));
- сама между режимами она не переключается.

Шифрования и расшифрования в ней нет: команд `encrypt` и `decrypt` не существует. Остальные ограничения — в разделе [«Известные ограничения»](#известные-ограничения).

## Как получить

`oncl` собирается отдельным архивом, не входящим в настольный пакет:
- Windows: `oncl-<version>-<flavor>.zip` (`win-x64`, `win-x86`, для Windows 7 SP1 — `win7-x64`, `win7-x86`);
- Linux и macOS: `oncl-<version>-<flavor>.tar.gz` (`linux-x64` под glibc 2.28, `osx` универсальный).

В архиве лежат программа, `README.md`, `docs/cli.md`, `THIRD-PARTY.txt` (лицензии включённого стороннего кода), `LICENSE` и `NOTICE`. Ни установщика, ни автообновления, ни автозапуска нет, и ничего не пишется вне путей, которые вы указали. Обновление — распаковка нового архива.

К релизу GitHub эти архивы не прикладываются. Берите их из артефактов сборки (хранятся 30 дней) или соберите из исходников ([`docs/dev/development.md`](../dev/development.md)).

```sh
tar -xzf oncl-<version>-linux-x64.tar.gz
./oncl-<version>-linux-x64/oncl --version
printf abc | ./oncl-<version>-linux-x64/oncl hash --algorithm sha256 --input -
```

В Windows распакуйте `.zip` и запускайте `oncl.exe` из этой папки. Пакет Visual C++ не нужен.

Из исходников: `cargo run -p oncl-cli -- …`.

## Первая команда

```sh
printf abc | oncl hash --algorithm sha256 --input -
```

Напечатает `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`. Ввод `--input -` (stdin) может занимать только одна роль. Две роли с stdin завершаются отказом до любого ввода-вывода.

## Команды

| Команда | Что делает |
|---|---|
| `hash --algorithm sha256\|gost2004\|gost2015-512 --input -` | Хеш файла или stdin |
| `sign --profile …` | Подпись закрытым ключом |
| `verify --profile …` | Проверка подписи; отсоединённая — с `--detached` |
| `extract` | Достаёт содержимое из CMS **без проверки подписи** |
| `inspect --profile certificate\|container\|cms\|named-key` | Показывает только открытые сведения |
| `extend --profile cms\|xml\|pdf --level b\|t\|lt\|lta` | Продлевает подпись (добавляет свидетельства), ключ не нужен |
| `timestamp acquire\|verify` | Получить или проверить метку времени (RFC 3161) |
| `jws sign\|verify`, `jwt encode\|verify\|decode` | JOSE: RS256 и ECGOST3410-2015-512 |
| `plugin call` | Вызвать плагин ([«Плагины»](#плагины-oncl-plugin)) |
| `plugin operations` | Показать операции, которые плагин объявил в манифесте |
| `batch run` | Выполнить пакет разных операций из JSON-файла |

Профили подписи: `cms`, `raw`, `digest-sha256|gost2004|gost2015-512`, `xml`, `wsse`, `pdf`, а также `cades-`, `xades-` и `pades-` с уровнями `b`, `t`, `lt`, `lta`. Профили проверки: `cms`, `xml`, `xml-kalkan`, `wsse`, `pdf` и те же семейства с уровнями. Профиль и алгоритм никогда не выводятся из имён файлов или из недоверенных данных.

## Подпись ключом

```text
oncl sign --profile cms --detached --input document.bin --output signature.der \
  --key signer.p12 --secret-file secrets/signer.secret --authorize \
  --root operator-root.der --pki-endpoint https://pki.example.test
```

- `--authorize` — ваше явное подтверждение: именно этот источник, профиль, ключ и место назначения. Пароль подтверждением не считается. Между запусками ключ не остаётся разблокированным. Перед использованием ключа всегда строго проверяются сертификаты и отзыв (`--offline` меняет только политику проверки, а не подпись).
- Источник ключа: `--key` (PKCS#12 или JKS; `--alias`, если записей несколько) **или** `--token-reader NAME --token-kind … --token-alias …` (настоящий PC/SC; проверялось только на эмуляторе, физического токена не было; отсутствующий считыватель — отказ).
- **Секреты никогда не передаются аргументами.** Используйте:
  - `--secret-file` — файл внутри существующего каталога, доступного только владельцу. Программа проверяет владельца и права каталога и файла, число ссылок и точки повторной обработки, и ничего не исправляет сама. В файле допустимо до 4096 байт пароля и один завершающий перевод строки; ничего не усекается;
  - `--secret-interactive` — ввод с клавиатуры. Отказ, если stdin — документ или не терминал. Backspace удаляет символ, Ctrl-U очищает ввод, Ctrl-W удаляет слово, Ctrl-C отменяет. Режим терминала восстанавливается при завершении и при ошибке.

Проверено: незащищённый каталог, слишком большой, отсутствующий секрет и секрет-каталог — отказ без использования ключа. Не проверена символическая ссылка (нужна привилегия, которой на тестовой машине нет). Отсутствие эха, восстановление терминала и Ctrl-C проверены на настоящем Windows ConPTY.

## Доверие, сеть и время

Доверие даёт только тот, кто запускает команду:

| Флаг | Что задаёт |
|---|---|
| `--root`, `--intermediate` | Корневые и промежуточные сертификаты, которым вы доверяете |
| `--pki-endpoint` | Адреса служб PKI (OCSP, CRL). Адреса из IP подходят сразу |
| `--pki-pin 'http://host:port=IP:port'` | Привязка DNS-имени к IP (это адрес, а не секретный PIN) |
| `--tsa-url`, `--tsa-policy OID` | Служба меток времени для уровней T/LT/LTA (для XAdES политика обязательна) |
| `--as-of <Unix-секунды>` | Своё «текущее время» (по умолчанию — UTC вашего компьютера) |
| `--offline` | Не обращаться к сети |
| `--configuration-bytes` | Бюджет на сертификаты (по умолчанию 16 МиБ; не больше 1024 файлов и 64 адресов) |

Сертификаты, пришедшие внутри документа, якорями доверия не становятся.

### Проверка CMS

`oncl verify --profile cms --input <signature.p7s> --root <корень НУЦ>` — единственная проверка подписи CMS в проекте. Она заменила старую команду `openncalayer cms-verify`.

- Набора доверия по умолчанию нет: корни НУЦ передайте через `--root`.
- Вход — DER или BER. С флагом `--pem` — PEM (только для CMS, до 16 МиБ, ровно один блок `CMS` или `PKCS7` и ничего вокруг). Текстовое поле демо-страницы даёт PEM, а её файл `.p7s` — DER.
- Проверка всегда строгая. Политика совместимости с NCALayer — выбор программы, которая встраивает SDK, а не ключ командной строки.
- Если время подписи ничем не доказано или данные об отзыве недоступны, вердикт `Indeterminate` (код выхода 3).

### CAdES и PAdES

С `--profile cades-*` или `pades-*` подпись, которая верна, но нарушает правила базового уровня, получает причину `Profile(SigningTimeForbidden|SigningTimeMissing|ContentTypeNotData|SigningCertificateMissing)`. Проверка подписи — `Passed`, вердикт — `Invalid` (код 2), уровень AdES не заявляется. PAdES от самого Kalkan несёт атрибут signing-time, который запрещает стандарт EN 319 142-1 (таблица 1), поэтому под `pades-*` он получает именно такой результат, а `--profile pdf` судит те же байты только по целостности и доверию.

## Отчёты, коды выхода и вывод

| Код выхода | Значение |
|---:|---|
| 0 | Выполнено, либо проверка `Valid` |
| 1 | Сбой выполнения, ввода, ресурсов, прав или использования |
| 2 | Проверка `Invalid` |
| 3 | Проверка `Indeterminate` (например, `--offline`, статус недоступен) |
| 4 | Пакет не завершён (есть элементы с ошибкой или не запущенные) |
| 130 | Отмена (Ctrl-C или Ctrl-Break) |

Таймаут `--timeout-seconds`: для одиночной команды — код 1 (`DeadlineExceeded`), для пакета — код 4 (частичный результат). Верхнеуровневое поле `code` отчёта пакета: `Completed`, `Partial`, `Cancelled`, `DeadlineExceeded`. Если отчёт после остановки доставить нельзя, в stderr пишется `report_delivery_failed_after_stop`, а коды 130 и 4 не меняются.

- `--json` пишет отчёт в stdout; `--report <новый путь>` пишет отдельный файл отчёта. Бинарный `--output -` вместе с JSON в stdout отклоняется до любого ввода-вывода.
- Ошибки использования не показывают значения аргументов.
- Результаты сначала пишутся во временный файл и публикуются **без перезаписи**: существующий файл никогда не заменяется.
- Документ и отчёт — не одна атомарная операция. Если отчёт не удалось записать уже после публикации документа, об этом сообщается честно; готовая подпись при этом не откатывается.

### Поля отчёта `--json`

Общие ключи: `operation_id` (число), `code` (`Completed` при успехе), `applied` (`NotApplied`, `Applied` или `Unknown` — применялся ли закрытый ключ). Поля, помеченные *текст*, — это отладочное представление типов SDK. Их можно читать, но они меняются вместе с SDK: в скриптах опирайтесь на `code`, `applied`, `verdict` и код выхода.

| Команда | Поля |
|---|---|
| `hash` | `operation_id`, `code`, `applied`, `digest` (hex в нижнем регистре), `bytes_in` |
| `sign`, `extend` | `operation_id`, `code`, `applied`, `profile`, `provenance`, `bytes_in`, `bytes_out`, `signer_count`; `xml` — если операция выдала отчёт XML |
| `extract` | `operation_id`, `code`, `applied` (`NotApplied`), `bytes_out`, `verified` (всегда `false`) |
| `verify` | `operation_id`, `code`, `applied` (`NotApplied`), `verdict` (`Valid`/`Invalid`/`Indeterminate`), `policy`, `checked_at` (секунды Unix), `ades_level` (текст или `null`), `signers`; `xml` / `pdf` для таких документов |
| `signers[]` | `signature`, `chain`, `validity`, `revocation`, `timestamp`, `key_usage`, `time_basis`, `claimed_signing_time` (секунды Unix или `null`), `ades_level`, `reasons` |
| `inspect` | `operation_id`, `code`, `applied` (`NotApplied`), `kind`, `container_integrity` (текст или `null`), `entries`; `cms` для CMS |
| `entries[]` | `alias`, `certificate_sha256`, `subject_cn`, `serial_hex`, `signature_algorithm_oid`, `public_key_algorithm_oid`, `not_before`, `not_after` (секунды Unix); каждое может быть `null` |
| `batch run` | `operation_id`, `code`, `attempted`, `completed`, `total`, `stop` (текст или `null`), `items[]` |
| `items[]` | `id`, `status` (`Completed`/`Failed`/`NotRun`), `code`, `subcode` (точная причина удалённой ошибки), `applied`, `verdict` (для verify), `published` (для элементов с выходом), `digest` `{algorithm, hex}` (для hash) |

Необязательные поля, если их нет, опускаются, а не равны `null`. `timestamp`, `jws`, `jwt` и `plugin call` печатают свои короткие отчёты. `plugin operations` — отчёт, описанный в разделе [«Плагины»](#плагины-oncl-plugin).

## JWS, JWT, WS-Security и пакеты

- `jws sign|verify --serialization compact|flattened|general [--detached]`; `jwt encode|verify|decode`. `jwt verify` принимает `--issuer`, `--audience`, `--leeway-seconds` и часы компьютера. `jwt decode` ничего не проверяет. Нагрузка JWS — до 256 КиБ, claims — до 64 КиБ.
- `sign|verify --profile wsse` с `--soap-version soap11|soap12`, `--wsse-role`, `--wsse-required-header`, `--wsse-timestamp-required`, `--wsse-timestamp-max-lifetime` (проверка). Для подписи ещё `--wsse-token-reference ncanode-x509-key-identifier|binary-security-token`, `--wsse-token-id`, `--wsse-body-id`, `--wsse-timestamp-id|created|expires`. Неподходящие флаги отклоняются до ввода-вывода.
- `batch run --manifest batch.json [--key … --secret-file …] --authorize` — элементы `hash`, `sign` (`cms|cms-detached|raw`), `verify` (необязательный `detached`), `extract`; у каждого уникальный `id`.
  - Весь манифест проверяется до любого ввода-вывода. Места назначения не должны существовать, а выход одного элемента не может быть входом другого.
  - Каждый готовый выход публикуется сразу, поэтому сбой или отмена позже не стирают прежние файлы. Плохой источник приводит к сбою только своего элемента.
  - Код выхода 0, 2 или 3 — по худшей проверке; 4 — если есть элемент с ошибкой или не запущенный; 130 — при отмене. Приоритет: 130 > 4 > 2 > 3 > 0.

Ctrl-Break в Windows завершает работу кодом 130.

## Плагины (`oncl plugin`)

```text
oncl plugin operations --manifest plugin.toml [--wasm plugin.wasm] [--json]
oncl plugin call       --manifest plugin.toml --module plugin.wasm --operation OP --caller LABEL
                       --output - [--allow-import NAME …] [запрос] [ключ и права]
```

Здесь вы сами называете вызывающего, операцию, импорты, ключ и базы PKI, а плагин ничего из этого расширить не может. Окон нет, браузерного origin нет, согласие не спрашивается: если плагину нужно диалоговое окно, он получает `InteractionRequired`. Обе команды только локальные; с `--endpoint` они отклоняются (`RemoteUnsupported`) до любого ввода-вывода.

### `plugin operations`: что объявлено

Показывает операции из манифеста (`[[operations]]`), чтобы права можно было выдавать, не читая TOML. Ключей не открывает и ничего не запускает.

| Флаг | Значение |
|---|---|
| `--manifest PATH` | `plugin.toml` (до 64 КиБ) |
| `--wasm PATH` | Дополнительно проверить модуль (до 16 МиБ): каждый импорт, который объявляет операция, должен быть в модуле, а каждый импорт модуля — объявлен. Код 1, если не подходит |
| `--json`, `--report PATH` | Отчёт в JSON |

```text
$ oncl plugin operations --manifest plugins/example/plugin.toml
plugin test.cli 1.0.0: 2 declared operation(s)
operation sign
  label: "a"
  server: yes  manual: no
  cli: yes
  imports: keys_sign_raw
  network: pki
  param file: document (at most 4096 bytes)
  key: raw, content param:file
    signs with your key: a raw signature of the content
operation manual-only
  label: "a"
  server: no  manual: yes
  cli: no (not for the CLI: server = false)
  imports: none
  network: none
  param file: document (at most 4096 bytes)
  key: none
```

Строка `cli:` показывает, выполнит ли `plugin call` эту операцию: нужны `server = true` и содержимое, которое программа умеет выполнять. Операция с содержимым `derived` помечается `cli: no (not runnable: derived content)`, и `plugin call` её отклоняет (`subcode=not-declared`). Слова об использовании ключа — английские тексты программы. `label` и XPath плагина — его собственный недоверенный текст, он печатается в кавычках. Плагин без `[[operations]]` печатает `declares no operations`.

JSON-отчёт: `code` (`Completed` или `InvalidInput`, когда `--wasm` не подходит), `applied` (всегда `NotApplied`), `plugin` `{id, version}`, `operations[]` и, с `--wasm`, `module` `{ok, error?}`. Поля каждой операции:

| Поле | Значение |
|---|---|
| `name`, `label` | Имя операции; английская метка плагина (недоверенная) |
| `server`, `manual` | Объявленные флаги |
| `runnable`, `derived` | `runnable` равен `false`, когда `derived` равен `true` |
| `cli` | `server` и `runnable`: такую операцию примет `plugin call` |
| `imports` | Объявленные импорты (максимум, который может назвать `--allow-import`) |
| `network` | `{"kind":"none"}`, `{"kind":"pki"}` или `{"kind":"urls","urls":[…]}` |
| `params[]` | `{name, kind}`: `document` (`max_bytes`), `text` (`max_chars`), `choice` (`choices`), `flag` или `locale` |
| `keys[]` | По одному на каждое использование ключа: `kind` (`raw`, `cms`, `cms_ex`, `xml`, `xml_ex`, `xades`), `content` (`param:<name>` или `derived`), `words`, `profile` |
| `xpaths` | Собственные XPath плагина (недоверенные), если есть |

### `plugin call`: флаги

| Флаг | Значение |
|---|---|
| `--manifest`, `--module` | Манифест (до 64 КиБ) и модуль (до 16 МиБ) одного плагина |
| `--operation OP` | Операция: объявленная с `server = true` или, для плагина без объявлений, метка от оператора |
| `--caller LABEL` | Метка, записываемая как вызывающий (не origin и не берётся у плагина) |
| `--allow-import NAME` | Какие импорты выдаются (повторяется, до 80, только известные). Для объявленной операции — только из её объявленных (без флага выдаются все объявленные). Для плагина без объявлений без флага — ни одного |
| `--output PATH\|-` | Куда писать ответ (без перезаписи; `-` — stdout, с `--json` в stdout не сочетается) |
| `--args-file PATH\|-` | Свободный JSON-запрос (до 256 КиБ) |
| `--param NAME=VALUE` | Параметр `text`, `choice` или `locale` объявленной операции (повторяется) |
| `--param-file NAME=PATH\|-` | Параметр `document` из файла (`-` — stdin; не больше одного stdin на команду) |
| `--param-flag NAME` | Параметр `flag` равен true; неназванный объявленный флаг равен false |
| `--key PATH [--alias A]` или `--key-name N --key-config FILE` | Ключ, привязанный как `--key-handle` (по умолчанию 1); см. [«Именованные источники ключей»](#именованные-источники-ключей) |
| `--secret-file PATH` или `--secret-interactive` | Пароль ключа, как у `sign` |
| `--authorize` | Обязателен с ключом |
| `--plugin-bytes` | Ваше согласие на использование ключа в объявленной операции (см. ниже); требует ключа |
| `--plugin-pki-endpoint GET=URL` / `POST=URL` | Точные базы PKI для проверки ключа плагина (до 16; нужен `network = "pki"`) |
| `--profile` | **Не принимается** (`ProfileFromManifest`): профиль подписи берётся из манифеста |

Общие флаги (`--json`, `--report`, доверие, `--timeout-seconds`) работают как у других команд. Нельзя сочетать `--args-file` и любой `--param*` (`InvalidCombination`). Ошибки использования, которые ничего не раскрывают и ничего не открывают: неверный `NAME=VALUE`, имя не по шаблону `^[a-z][a-z0-9_]{0,31}$`, больше 16 параметров одного вида, два источника stdin (`StdinConflict`), stdin вместе с `--secret-interactive`.

### Типизированные параметры

Для объявленной операции без `--args-file` программа строит запрос из шаблона манифеста так же, как ручное окно. Всё проверяется до чтения секрета и открытия ключа. Операции без параметров флаги не нужны.

- Каждый объявленный параметр задаётся ровно один раз (флаг можно опустить: он false). Необъявленное имя — `unknown-param`, повтор — `duplicate-param`, пропуск — `missing-param`.
- Документ — только через `--param-file`, text, choice и locale — только через `--param` (иначе `param-wrong-kind`).
- Выбор `choice` — одно из объявленных значений. `locale` — `ru`, `kk` или `en`. `text` — не длиннее `max_chars`. Подписываемый текст не может содержать управляющие, двунаправленные и невидимые символы (кроме `\n` и `\t`; `\r` тоже запрещён) — `param-invalid-value` или `param-too-large`.
- Файл документа не больше объявленного `max_bytes`: больше — `InputLimit` (`param-too-large`), пустой — `param-invalid-value`.
- Весь запрос — до 256 КиБ (`request-too-large`).

Текстовый параметр, который читает профиль ключа (`element = "param:xpath"`), сверяется с согласием `--plugin-bytes`: оно покрывает ровно профиль с этим значением, и плагин, подписывающий другой элемент, получит `options-mismatch`.

Плагин **без** `[[operations]]` принимает только `--args-file`. `--param*` или отсутствие `--args-file` дают `PermissionDenied` (`not-declared`). `--plugin-bytes` на него не действует (об этом будет предупреждение).

`plugin call` запускает только операции с `server = true`. Плагины из `plugins/` объявляют 30 операций, все только для ручного окна ([руководство](manual-plugins.md)), поэтому `oncl plugin call` отказывает каждой с `subcode=not-declared`. `plugin operations` их перечисляет.

### Согласие и аудит

CLI ничего не спрашивает. Для использования ключа нужен `--plugin-bytes`: **согласие даёт тот, кто запускает команду**. Флаг означает: «я принимаю, что плагин сам выбирает байты, которые подпишет ключ».
- При свободном `--args-file` разрешение привязывает только операцию, вид подписи и параметры.
- При типизированных параметрах оно привязывает и содержимое: подписываемые байты должны точно совпасть с переданным значением параметра (текст как UTF-8, документ как байты файла), иначе отказ до ключа (`content-mismatch`). Подпись по готовому хешу заранее не вычислить, и она отклоняется (`content-binding-unavailable`).
- Без флага использование отклоняется до применения ключа (`not-granted`).

Разрешение покрывает одно использование объявленного вида с точно объявленными параметрами. Несовпадение — `options-mismatch`, второе использование за вызов — `key-use-spent`.

CLI не ведёт журнала; запись для оператора — это stderr. Перед использованием ключа пишутся две строки: доверенные факты разрешения (никогда не документ, не значение параметра, не секрет) и обычная строка `private_use`:

```text
oncl: plugin_use operation_id=7 plugin=test.cli version=1.0.0 package=2:<sha256 of manifest+module> operation=sign caller=local-operator declared=true grant=cli-plugin-bytes content_sha256=<sha256 of the bytes signed> content_len=14 prehashed=false options_sha256=<sha256 of the forced options> ticket=<sha256 digest of the ticket>
oncl: private_use operation_id=7 applied=Applied succeeded=true
```

`grant=cli-plugin-bytes` — ваше согласие. `package=2:…` — хеш двух названных вами файлов (манифеста и модуля). Отклонённое использование пишет вместо этого `oncl: plugin_refused operation_id=… subcode=… plugin=… operation=…`, ключ при этом не применяется.

### Коды выхода и отказы

| Код выхода | Значение |
|---:|---|
| 0 | Выполнено (для `plugin operations` — перечислено и, с `--wasm`, модуль подходит) |
| 1 | Любой отказ или сбой, включая ошибки использования и неподходящий `--wasm` |
| 130 | Отмена |

Сбой печатает в stderr `oncl: <code>; subcode=<id>; applied=<NotApplied|Applied|Unknown>` (`subcode=` — если он есть) и ничего в stdout. JSON-отчёт при отказе плагина не печатается. Подкоды `plugin call`:

| Код | `subcode` | Причина |
|---|---|---|
| `PermissionDenied` | `not-declared` | Операция не объявлена, не `server = true` или производная; импорт сверх объявленного; типизированные параметры (или нет `--args-file`) у плагина без объявлений; плагин вызвал необъявленное имя |
| `PermissionDenied` | `no-key-use` | `--key` для операции, которая не использует ключ |
| `PermissionDenied` | `network-not-declared` | `--plugin-pki-endpoint` без `network = "pki"` |
| `PermissionDenied` | `not-granted` | Использование ключа без `--plugin-bytes` (или не тот плагин или операция) |
| `PermissionDenied` | `key-mismatch` | Использован другой ключ, чем открытый командой |
| `PermissionDenied` | `content-mismatch`, `content-binding-unavailable` | Плагин подписывает не те байты, что переданы, либо подпись по хешу |
| `PermissionDenied` | `options-mismatch`, `kind-mismatch`, `key-use-spent`, … | Использование ключа не совпадает с объявлением (весь список — в [дизайне](../design/manual-plugins.md), §4.8). Ключ не применялся, кроме `key-use-spent` (первое использование остаётся `Applied`) |
| `InvalidInput` | `unknown-param`, `duplicate-param`, `missing-param`, `param-wrong-kind`, `param-invalid-value`, `invalid-template` | Параметр неверен |
| `InputLimit` | `param-too-large`, `request-too-large` | Параметр или запрос больше предела |

### Примеры

Объявленная операция с документом и ключом (манифест объявляет `sign` с `server = true`, параметр `file` — документ, `keys_sign_raw` и `network = "pki"`):

```sh
oncl plugin operations --manifest plugin.toml                    # что можно выдать?
oncl plugin call --manifest plugin.toml --module plugin.wasm \
  --operation sign --caller ops-laptop --output signature.b64 \
  --param-file file=statement.pdf \
  --key signer.p12 --secret-file secrets/signer.secret --authorize --plugin-bytes \
  --root nca-root.der --pki-endpoint https://pki.example.test \
  --plugin-pki-endpoint GET=https://pki.example.test/ocsp --plugin-pki-endpoint POST=https://pki.example.test/ocsp
```

Операция без ключа с параметрами text, choice и flag:

```sh
oncl plugin call --manifest plugin.toml --module plugin.wasm --operation note \
  --caller ops-laptop --output - \
  --param text='hello' --param pick=two --param lang=kk --param-flag on
```

Плагин без объявлений (метку и импорты называете вы, запрос свободный):

```sh
oncl plugin call --manifest plugin.toml --module plugin.wasm --operation hash \
  --caller ops-laptop --allow-import hash --args-file request.json --output -
```

`plugin call --json` печатает `{operation_id, code: "Completed", applied, response_bytes}` после записи ответа (сам ответ идёт в `--output`).

## Параметры XML в режиме совместимости (`--legacy`)

`sign --profile xml|xades-b|xades-t|xades-lt --legacy` подписывает так, как это делают Kalkan и NCALayer, с той же строгой проверкой перед использованием ключа. Флаги:

- `--legacy-element`, `--legacy-parent`, `--legacy-namespace PREFIX=URI`, `--legacy-other-prefix-uri`;
- `--legacy-placement document-element|first-child`;
- `--legacy-signature-method` и `--legacy-digest-method` (`rsa-sha256|gost2004|gost2015-512`);
- `--legacy-signed-info-c14n`, `--legacy-transform enveloped|inclusive|…` (enveloped первым и один раз, не больше одной канонизации);
- `--signature-id`, `--legacy-signing-time-id|--legacy-signing-time|--legacy-signing-time-reference`;
- `--legacy-line-breaks`, `--legacy-base64-line-breaks on|off`;
- `--legacy-output as-is|serialize` с `--legacy-xml-declaration`, `--legacy-standalone-no`, `--legacy-keep-outer-whitespace`;
- для XAdES — `--legacy-chain CERT.der` (открытые сертификаты издателей, до 16 файлов по 16 КиБ).

Неподдерживаемые сочетания дают `InvalidCombination` или `TsaRequired` до любого ввода-вывода: legacy CMS, PDF, WSSE и XAdES-LTA, `--add`, `--target-id`, XML-параметры для XAdES, уровень с метками времени без `--tsa-url`, неверные привязки пространств имён, управляющие символы. Ни один флаг не принимает путь к ключу, URI алгоритма или произвольное преобразование.

XAdES T/LT/LTA (и baseline, и legacy) требуют `--tsa-url` **и** `--tsa-policy OID`, иначе `TsaPolicyRequired` до ввода-вывода. Токен с политикой, отличной от запрошенной, отклоняется уже после использования ключа (`applied=Applied`). Baseline XAdES требует ещё `--signature-id`.

## Именованные источники ключей

`--key-name NAME --key-config keys.json` (sign, jws/jwt, batch, plugin) подставляет вместо пути ключ по имени из JSON-файла. Файл не содержит секретов: до 64 КиБ, до 64 записей, неизвестные поля запрещены, относительные пути считаются от файла. Он определяет, какой контейнер или считыватель открывается под выданным именем, поэтому читается **как файл секрета**: из каталога только для владельца, только обычный файл, с теми же проверками.

```json
{"keys":[{"source":"file","name":"main","path":"signer.p12","alias":null},
         {"source":"token","name":"card","reader":"<PC/SC reader>","kind":"kaztoken","alias":"<key alias>"}]}
```

Имя — идентификатор ключа для `--authorize` (`named:NAME`). Путь и считыватель в командной строке не появляются; `--key-name` несовместим с `--key` и `--token-reader`. `inspect --profile named-key --key-name … --key-config … --secret-file …` читает открытые сведения именованного источника (файл, JKS, PKCS#12, токен) без использования закрытого ключа.

## Токены и эмулятор

`--token-reader` и записи токенов в `--key-config` проверяются в тестах на программных токенах репозитория: соберите с `--features token-emulator` и задайте `ONCL_TOKEN_EMULATOR=<oncl-token emulator config.toml>`. Переменная существует только в этой сборке (в релизных — никогда). Нечитаемый файл — отказ, а не переход на другой путь. Физический токен не использовался.

## Отмена и таймаут пакета

Пакет, остановленный Ctrl-C, Ctrl-Break или `--timeout-seconds`, всё равно выдаёт итоговый отчёт: по элементам (`Completed|Failed|NotRun`), `applied`, `published` и `digest`. Код 130 при отмене, 4 при таймауте. Файл `--report`, записываемый после остановки, создаётся сразу, без перезаписи. Прерванный элемент — `Failed` с кодом `Cancelled` или `DeadlineExceeded`. Ctrl-C на запросе секрета — `Cancelled` (130).

Если пакет остановлен не отменой и не таймаутом, а итоговый отчёт доставить нельзя (закрытый stdout, недоступный `--report`), код выхода 1. Только остановка по отмене или таймауту сохраняет 130 или 4 поверх сбоя отчёта.

## Известные ограничения

- **Терминалы.** Отсутствие эха, восстановление режима и Ctrl-C проверены только на Windows ConPTY; `termios` и сигналы Linux и macOS не проверялись.
- **Уровни XAdES.** Заявление XAdES-LT/LTA (и профили проверки `xades-lt`/`xades-lta`) требует штампа подписи, значений отзыва и `CertificateValues` со всеми сертификатами пути подписанта выше листа, включая якорь (ETSI EN 319 132-1 §5.4.2). `sign --profile xades-lt` всё это выпускает. Документ без них заявляется как `T`, а `xades-lt` его отклоняет (`InvalidInput`). Это строже, чем у CAdES/PAdES (там для LT достаточно штампа и статуса отзыва); асимметрия пока намеренная. Проверка охватывает только путь подписанта, а не путь службы меток времени. Добавление подписи `sign --profile xml --add` поверх подписи, ссылка которой покрывает позицию новой подписи (весь документ, объемлющий элемент или член Manifest, если она не отбрасывает подписи), отклоняется до использования ключа (`InvalidInput; applied=NotApplied`).
- **Большой CRL в XAdES.** `verify --profile xades-b|t|lt|lta` принимает встроенный CRL до 32 МиБ на CRL и 48 МиБ всего: XAdES-LT от NCANode/Kalkan с полным CRL НУЦ (около 27 МБ) проверяется. CRL не от издателя подписанта статуса не даёт; CRL, перечисляющий подписанта, отзывает его. Но при **создании** подписи или продлении XAdES-LT/LTA полный CRL НУЦ (около 20 МБ) не помещается: CRL внутри подписи — не больше примерно 190 КиБ, иначе `MetadataLimit` (число вычислено по коду, тестом не измерено). См. `docs/dev/sdk.md`.
- **Долгосрочный статус (`lt`/`lta`).** Статус отзыва внутри подписи оценивается на момент, который доказывает штамп подписи, а не по вашим часам. Даже при сдвинутых позже `--as-of` или часах компьютера документ CAdES/PAdES/XAdES `lt`/`lta` судится по тому, что было свежим в доказанный момент, если сертификаты подписанта и цепочки тогда были действительны (для тестовых файлов NCANode, чьи штампы здесь не проверяются, это не обещано). Статус с `nextUpdate` свеж, пока доказанное время ему предшествует. Статус без него (OCSP НУЦ) должен быть выпущен не раньше чем за 300 с до этого момента. Отклоняются статусы: выпущенные после вашего времени проверки (для OCSP — более чем через 300 с), уже просроченные на доказанный момент, недоверенные, отозванные не позже доказанного момента и относящиеся к другому сертификату. Подпись без проверенного штампа (`b`) судится по текущему времени. Правило и ссылки на стандарты: `docs/dev/sdk.md`.
- **Свидетельства.** Подпись CAdES-LT/LTA и PAdES-LT/LTA и `extend` без ключа через CLI подтверждены. Материалы передаются так: `--evidence-certificate`, `--evidence-ocsp`, `--evidence-crl` (открытые файлы DER, до 64 каждого вида, до 256 КиБ каждый, до 8 МиБ всего; допустимы только с CAdES/PAdES sign и `extend`; это границы подписи, а квота 32 МиБ на CRL — проверки). Обязательны `--tsa-url` и `--tsa-policy`. Ответ OCSP без `nextUpdate` должен быть выпущен не раньше чем за 300 с до штампа, иначе он должен нести `nextUpdate` позже штампа; ни один ответ не может быть выпущен после `--as-of`. Подпись LT/LTA без сертификатов и OCSP/CRL — `EvidenceMaterialRequired` до ввода-вывода; недостаточный материал обнаруживается только после использования ключа (`applied=Applied`). Подпись и продление PAdES независимо проверены pyHanko.
- **JKS.** Подпись работает с той же строгой проверкой, что и PKCS#12 (`--alias` выбирает запись). Подпись ГОСТ проверяет сам SDK, независимого ГОСТ-оракула нет. Режим `--legacy` отклоняет подписанта ГОСТ-2015 (`InvalidInput`, до использования ключа); baseline XML с ГОСТ работает.
- **Место назначения.** Нужен том с поддержкой жёстких ссылок (FAT, exFAT и SMB дают сбой после использования ключа). Память WASM плагина жёстко ограничена 1 МиБ.
- **Папка результата в Linux и macOS.** Результат пишется через временный файл в той же папке, а такой файл отказывается жить в папке, куда может писать группа или остальные (если нет «липкого» бита, как у `/tmp`). В Ubuntu и Fedora новые папки создаются с режимом `0775`: подпись в такую папку завершится ошибкой `Io` (`applied=NotApplied`) ещё до использования ключа. Исправление: `chmod g-w <папка>` или другая папка. Для окна «Инструменты» правило, судя по коду, то же, запуском не проверялось.
- `inspect --profile container` требует `--alias`.
- Шифрования и расшифрования в CLI нет. Библиотека `oncl-pki` умеет CMS EnvelopedData/AuthEnvelopedData только для RSA-получателей; профилей ГОСТ нет — их не с чем сверить.

## Удалённый режим (`--endpoint`)

```sh
oncl --endpoint https://signing.internal:13579 --token-file client.token --ca-file ca.pem \
  sign --profile cms --key-name corporate-signing --authorize --input doc.bin --output doc.p7s
```

Операция выполняется на сервере из [server.md](server.md) / [http-api.md](http-api.md). Клиент — `oncl_api::client::ApiClient` (feature `client` крейта `oncl-api`).

- **Пути.** Все локальные пути читает и пишет клиент. Документы идут потоком, результаты сначала пишутся во временный файл и публикуются без перезаписи, как при локальной работе. Сервер никогда не открывает путь клиента: путь в любом строковом поле запроса отклоняется (`remote::server_cannot_open_client_path`).
- **Фиксация результата.** Результат публикуется, только когда получены итоговая запись `final`, закрывающий разделитель multipart и конец HTTP-ответа. Если ответ оборвался раньше, ничего не публикуется, временных файлов не остаётся, печатается `oncl: ResponseLost; applied=Unknown` (`NotApplied` для операций без ключа), код выхода 1. **Автоповтора и обещания «ровно один раз» нет**: сервер мог применить ключ (смотрите его журнал аудита). Прежние файлы не затрагиваются.
- **`applied`.** Сервер начинает закрытую операцию, только приняв всё тело запроса. Сбой при отправке тела — `NotApplied`. Потерянный ответ после последнего байта тела — `Unknown`, если запрос мог использовать ключ. Типизированный отказ или итоговая запись несут значение сервера.
- **Токен доступа.** `--token-file PATH` (каталог только для владельца, те же правила и предел 4096 байт, что у `--secret-file`) или `--token-stdin` (тогда stdin — не документ). Не через аргументы и не через переменную окружения. Токен не попадает ни в диагностику, ни в отчёт, ни в ошибку; сообщения об ошибках не содержат тела ответа, только стабильный код, статус HTTP и код сервера.
- **Соединение.** `https://` использует встроенные корни webpki; `--ca-file` (PEM или DER, повторяется) *заменяет* их для частного сервера. Флага отключения проверки нет. `http://` принимается только для `localhost`, `127.0.0.0/8`, `::1`. Для другого хоста нужен `--allow-plain-http` (токен и документы идут без шифрования: только в защищённой внутренней сети). Каждый такой запуск пишет в stderr предупреждение `oncl: warning: --allow-plain-http sends the API token and every document over an unencrypted, unauthenticated connection …`. Без флага такой адрес отклоняется до соединения (`PlainHttpRefused`). Перенаправления (3xx) не выполняются (токен не пересылается: `UnexpectedStatus (HTTP 307)`), переменные прокси игнорируются.
- **Ключи.** `--key-name NAME` ссылается на ключ оператора на сервере (секрет с клиента не нужен). Ключ покидает клиента только с `--key PATH --secret-file … --inline-key` (и `inspect --profile container … --inline-key`): контейнер и пароль идут как части запроса, только в памяти; на сервере должна быть включена настройка `inline_pkcs12` (глобально и для токена). `--token-reader` и `--key-config` — локальные и отклоняются.
- **Полномочия остаются у оператора сервера.** Корни доверия, политика проверки, сеть PKI, часы, TSA, issuer и audience JWT и установка плагинов — настройки сервера. Эти флаги отклоняются с `RemoteUnsupported` до любого ввода-вывода: `--root`, `--intermediate`, `--pki-endpoint`, `--pki-pin`, `--tsa-url`, `--tsa-policy`, `--offline`, `--as-of`, `--configuration-bytes`, `timestamp acquire --tsa/--algorithm`, `timestamp verify --policy-oid`, `jwt verify --issuer/--audience/--leeway-seconds`, `inspect --alias`, любая команда `plugin`. `sign` по-прежнему требует `--authorize`. Отклоняются и параметры, которых нет в протоколе: WS-Security сверх `--soap-version` и `--wsse-body-id`, XML-параметры сверх элемента, родителя, методов подписи и дайджеста.
- **Что можно.** `hash`, `verify`, `extract`, `sign` (cms, cades-*, xml, wsse, xades-b/t, pdf, pades-*, а также `--legacy` xml/xades-b/xades-t), `extend` (cms/pdf t|lt|lta, xml lt|lta), `inspect`, `timestamp`, `jws`, `jwt`, `batch run`. Профили `raw`, `digest-*` и XAdES LT/LTA для подписи недоступны (используйте `xades-t`, затем `extend` без ключа). Свидетельства передаются через `--evidence-certificate/-ocsp/-crl` как открытые части запроса.
- **Причины отказа.** Типизированный отказ с `subcode` печатается как `oncl: <code>; subcode=<id>; applied=<state>`. Команд плагинов удалённо нет.
- **Отчёты и коды выхода** — как у локальных. Вердикт, политика и проверки по подписанту совпадают с локальным запуском. Отличия: в протоколе нет подробностей структуры PDF/XML и верхнеуровневого уровня AdES (он опущен, а не выдуман); `time_basis` — вариант (`time_basis_unix` содержит момент); `bytes_in` — отправленные клиентом байты документа, `bytes_out` — полученный результат; факты `timestamp` — объект. `jwt decode` пишет текст нагрузки, декодированный сервером (недопустимый UTF-8 заменяется).
- **Целостность ответа.** Каждый артефакт, названный итоговой записью, должен быть получен один раз точной длины: извлечение (`bytes_written`) и токены меток времени (`bytes_out`), создание JWS и JWT тоже. Часть неверного размера ничего не публикует (`ProtocolViolation: artifact length differs from the final record`, код 1). Для подписи и продления CMS/CAdES/XML/PDF длина не сверяется: сервер берёт её из подготовленного выхода, поэтому там проверяются только тождество и число частей.
- **Пакет.** Манифест читается на клиенте; источник, который нельзя открыть, ломает только свой элемент. Выходы готовятся в одном хранилище (общий каталог назначения, иначе `--temporary-directory`, иначе `.`; он должен быть на том же томе) и ставятся на место жёсткими ссылками после итоговой записи. Если выходы лежат в разных каталогах, ссылку заранее пробуют в каждом *до любого запроса* (`DestinationNotLinkable`, `NotApplied`): ключ не используется для результата, который нельзя поставить на место. Серверу нужно право `batch` у токена.
- **Если сервер отвечает, пока клиент ещё отправляет.** Сервер читает и отбрасывает остаток тела не дольше секунды и около 8 МиБ, и клиент в этих пределах читает типизированный ответ. Если клиент отправляет дольше, соединение сбрасывается и ответ может потеряться: итог — сбой соединения с `applied=NotApplied` (тело было неполным). Отмена и таймаут проверяются каждые 50 мс, поэтому Ctrl-C завершает ожидание ответа за несколько секунд (код 130, `applied=Unknown`, если ключ мог использоваться и тело отправлено полностью, иначе `NotApplied`). Повторов нет.
- **Что проверено.** Документы по 1 ГиБ и RSS, подпись PDF и XML и продление PAdES до LT/LTA через клиент проверены приёмочным прогоном `cargo xtask platform-proof` ([`docs/dev/platform-acceptance.md`](../dev/platform-acceptance.md)). Не проверялось: Linux и macOS, Windows 7, TLS с закреплённым ключом (только файл CA или сертификата сервера), `jws add`, `cms add` и `wsse` по удалённому пути, прямая удалённая подпись PAdES LT/LTA (покрыта тестами `oncl-api` на уровне HTTP).
- Шифрования и расшифрования нет ни командой, ни маршрутом протокола.
