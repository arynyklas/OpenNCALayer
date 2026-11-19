# Издателям плагинов

Как собрать плагин стороннего издателя так, чтобы OpenNCALayer принял выпуск. Устройство всей схемы описано в [`docs/design/publishers.md`](../design/publishers.md): почему пересборка обязательна, что подписывает издатель, какие проверки проходит PR.

## Сборка в эталонном сборщике

Пакет `.onclp`, который вы подписываете в своей роли, CI OpenNCALayer собирает заново из вашего архива исходников в эталонном сборщике и сравнивает побайтно (проверки 19 и 21 в [`publishers.md`](../design/publishers.md#проверки-pr-издателя-дополняют-111)). Совпадение обещано только внутри сборщика: это образ `ghcr.io/arynyklas/oncl-plugin-builder` с конкретным digest из [`publishers/builders.toml`](../../publishers/builders.toml). Этот digest вы пишете в `source.builder`. Сборка тем же `cargo` на своей машине годится для разработки, но её байты могут не совпасть.

В образе:

- Debian 13 slim, закреплённый по digest;
- Rust 1.99.1 с целью `wasm32-unknown-unknown`, без rustup: ваш `rust-toolchain.toml` не читается;
- gcc для build-скриптов и процедурных макросов, git;
- `oncl-pack`: делает канонический архив исходников, скачивает зависимости, собирает и проверяет пакет.

Образ работает от пользователя 10001. Каталог Cargo `/cargo` монтируйте томом, а рабочий каталог `/build` — свежим томом на каждый запуск: сборка распаковывает исходники в `/build/src` и не начнёт работу, если там что-то уже лежит.

### Что нужно

- Docker или Podman (в командах ниже `docker` можно заменить на `podman`). На Windows и macOS подойдёт Docker Desktop. Команды написаны для bash; в PowerShell замените `$PWD` на `${PWD}` и переносы строк `\` на `` ` ``.
- Крейт плагина: один `cdylib`, рядом `plugin.toml`, версия в нём равна версии крейта. `Cargo.lock` рабочего пространства лежит в архиве. Зависимости берутся только из crates.io и из git с закреплённым `rev`.
- В архиве нет `.cargo/config` и `.cargo/config.toml` ни в корне, ни по пути к крейту: такой файл мог бы подменить источники зависимостей или ход сборки, поэтому сборщик отказывается его читать.

Ниже `IMAGE` — образ по digest, например:

```sh
IMAGE=ghcr.io/arynyklas/oncl-plugin-builder@sha256:<digest из publishers/builders.toml>
```

### 1. Архив исходников

Архив должен быть ровно таким, какой делает `oncl-pack source`: один корневой каталог `src/`, только файлы и каталоги, записи по порядку путей, владелец 0, время 1980-01-01, режим 0644 или 0755, gzip сборщика. Полные правила — в разделе [«Архив исходников»](../design/publishers.md#архив-исходников). Архив, собранный другим `tar`, не пройдёт проверку, даже если файлы в нём те же.

Архив из ревизии git (рекомендуется: в архив попадает всё дерево ревизии, как его хранит git, без каталога `.git`):

```sh
docker run --rm --network=none --read-only \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
  -v "$PWD:/repo:ro" -v "$PWD/dist:/out" \
  "$IMAGE" source --git /repo --rev v1.2.0 --out /out/kz.ecc.market-1.2.0.src.tar.gz
```

Переменные `GIT_CONFIG_*` разрешают git читать смонтированный репозиторий, владелец которого не пользователь 10001.

Архив из каталога: в архив попадает каждый файл каталога, кроме `.git`. Подходит для исходников вне git.

```sh
docker run --rm --network=none --read-only \
  -v "$PWD/sources:/sources:ro" -v "$PWD/dist:/out" \
  "$IMAGE" source --dir /sources --out /out/kz.ecc.market-1.2.0.src.tar.gz
```

Признак исполняемого файла берётся из файловой системы. Docker Desktop показывает файлы, смонтированные из Windows, с режимом 0777: архив из такого каталога получит у каждого файла режим 0755 и не совпадёт с архивом той же ревизии из git. Из Windows делайте архив с `--git`.

Команда печатает sha256 архива. Он и длина файла идут в `source.archive_sha256` и `source.archive_length`. Проверить готовый архив:

```sh
docker run --rm --network=none -v "$PWD/dist:/out:ro" "$IMAGE" check /out/kz.ecc.market-1.2.0.src.tar.gz
```

Команда печатает sha256 и длину архива или объясняет, почему архив не канонический.

### 2. Зависимости

Единственный шаг с сетью. Он распаковывает архив и скачивает в том `/cargo` всё, что перечисляет `Cargo.lock` (`cargo fetch --locked`); код из архива при этом не запускается. `--path` — каталог крейта внутри `src/`, то есть `source.path`; для крейта в корне архива укажите `--path ''`.

```sh
docker volume create oncl-cargo
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v oncl-cargo:/cargo --mount type=volume,dst=/build -v "$PWD/dist:/in:ro" \
  "$IMAGE" fetch --source /in/kz.ecc.market-1.2.0.src.tar.gz --path crates/market
```

### 3. Сборка

Сборка идёт без сети, с файловой системой образа только для чтения:

```sh
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --cpus 8 --memory 8g --pids-limit 4096 \
  -v oncl-cargo:/cargo --mount type=volume,dst=/build \
  -v "$PWD/dist:/in:ro" -v "$PWD/out:/out" \
  "$IMAGE" build --source /in/kz.ecc.market-1.2.0.src.tar.gz --path crates/market --out /out
```

`--mount type=volume,dst=/build` без имени тома каждый раз даёт новый пустой том; Docker удалит его вместе с контейнером (`--rm`).

`oncl-pack build`:

1. проверяет, что архив канонический, в нём есть `src/<path>/Cargo.toml` и `src/<path>/plugin.toml` и нет `.cargo/config*` по пути к крейту;
2. собирает крейт для `wasm32-unknown-unknown` с `--release --frozen`. Окружение очищено (как после `env -i`), `SOURCE_DATE_EPOCH=315532800`. Профиль `release` дополняется настройками `codegen-units = 1`, `incremental = false`, `debug = false`, `strip = true`; `opt-level`, `lto` и `panic` остаются вашими. Пути сборки заменяются в модуле постоянными именами: `/cargo`, `/rustc`, `/target`, `/workspace` и `/plugin`;
3. проверяет пакет так же, как демон перед установкой: манифест, версию крейта, ABI модуля, `min_core`;
4. собирает крейт второй раз в чистом каталоге и сравнивает. Если две сборки различаются, пакет не выдаётся: что-то в вашем крейте или его зависимостях собирается неповторяемо. Частые причины — порядок `HashMap` в процедурном макросе и время или случайные данные в `build.rs`.

В `/out` появляется один файл `<id>-<версия>.onclp`, команда печатает его sha256. Этот хеш и длину пакета вы подписываете в своей роли.

Опция `--jobs N` ограничивает параллельность Cargo; на байты пакета она не влияет.

На 8 ядрах порт `plugins/eot` этого репозитория скачивал зависимости 6 с, а обе сборки в одном контейнере заняли 20 с. Образ без сжатия занимает около 1,5 ГБ.

### 4. Проверка выпуска

Любой может пересобрать опубликованный выпуск и сравнить байты. Из выпуска `pub-<издатель>-<sha256 пакета>` в Releases OpenNCALayer скачайте `<id>-<версия>.src.tar.gz`, затем:

```sh
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --mount type=volume,dst=/cargo --mount type=volume,dst=/build -v "$PWD:/in:ro" \
  "$IMAGE" verify --source /in/kz.ecc.market-1.2.0.src.tar.gz --path crates/market \
  --sha256 <sha256 пакета>
```

`verify` сам скачивает зависимости, поэтому ему нужна сеть. Если зависимости уже есть в томе `/cargo` после `fetch`, добавьте `--offline` и `--network=none`. Вместо `--sha256` можно указать сам пакет: `--package /in/<id>-<версия>.onclp`. Код выхода 0 означает, что пересборка дала те же байты. Иначе команда пишет оба хеша.

### Если не получилось

| Сообщение | Что делать |
|---|---|
| `the archive is not canonical` | Архив сделан не `oncl-pack source` или изменён после. Сделайте его заново командой из шага 1 |
| `the archive has src/….cargo/config…` | Уберите `.cargo/config*` из исходников; нужные настройки перенесите в `Cargo.toml` |
| `the reference build failed (were the crates fetched first…)` | Выполните шаг 2 с тем же томом `/cargo`; проверьте, что `Cargo.lock` в архиве актуален |
| `two builds of the same sources differ` | Сборка неповторяема: ищите неустойчивый порядок или время в процедурных макросах и `build.rs` |
| `unpacking the archive (the work directory must be fresh)` | Монтируйте в `/build` новый том на каждый запуск |
| `detected dubious ownership` от git | Передайте переменные `GIT_CONFIG_*` из шага 1 |

## Образ сборщика

Это раздел для владельца проекта.

- Образ собирается из [`xtask/assets/plugin-builder/Dockerfile`](../../xtask/assets/plugin-builder/Dockerfile). Контекст сборки — корень репозитория, `oncl-pack` собирается из того же коммита. Базовый образ закреплён по digest, архивы тулчейна — по sha256 из `channel-rust-<версия>.toml`. Версия Rust в Dockerfile совпадает с `rust-toolchain.toml`, это проверяет тест.
- Публикует образ workflow [`plugin-builder.yml`](../../.github/workflows/plugin-builder.yml), его запускают вручную на `main`. Он собирает образ и дважды собирает в нём порт (тест `image` крейта `oncl-pack`). Затем отправляет образ в ghcr.io с тегом коммита, подписывает аттестацию происхождения и выводит в сводке готовую запись для `publishers/builders.toml`.
- Сборщиком образ становится только после PR владельца, который добавляет запись в конец `publishers/builders.toml`. Записи там не меняются и не удаляются, иначе старые выпуски нельзя будет пересобрать. Схему файла описывает `xtask/src/publishers/builders.rs`.
- Собрать и проверить образ локально:

  ```sh
  git archive HEAD | docker build -f xtask/assets/plugin-builder/Dockerfile -t oncl-plugin-builder -
  ONCL_BUILDER_IMAGE=oncl-plugin-builder cargo test -p oncl-pack --test image -- --ignored --nocapture
  ```

  Без `ONCL_BUILDER_IMAGE` тест сам собирает образ из `HEAD`. На машине с 8 ядрами сборка образа занимает около 2 минут, тест — около минуты.
