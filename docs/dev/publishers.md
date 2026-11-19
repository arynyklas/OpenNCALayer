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

Архив должен быть ровно таким, какой делает `oncl-pack source`: один корневой каталог `src/`, только файлы и каталоги, записи по порядку путей, владелец 0, время 1980-01-01, режим 0644 или 0755, gzip сборщика. В именах нет `\`, `:`, управляющих символов, имён устройств Windows (`CON`, `NUL`, `COM1` и т. п.) и точки или пробела в конце. Полные правила — в разделе [«Архив исходников»](../design/publishers.md#архив-исходников). Архив, собранный другим `tar`, не пройдёт проверку, даже если файлы в нём те же.

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

Единственный шаг с сетью. Он распаковывает архив и скачивает в том `/cargo` всё, что перечисляет `Cargo.lock` (`cargo fetch --locked`); код из архива при этом не запускается. `--path` — каталог крейта внутри `src/`, то есть `source.path`; для крейта в корне архива укажите `--path=`.

Заводите отдельный том `/cargo` на каждый архив и удаляйте его после проверки: сборка видит его только для чтения, но один и тот же том для разных исходников не нужен.

```sh
docker volume create oncl-cargo-market-1.2.0
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v oncl-cargo-market-1.2.0:/cargo --mount type=volume,dst=/build -v "$PWD/dist:/in:ro" \
  "$IMAGE" fetch --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market
```

### 3. Сборка

Сборка выполняет код исходников (`build.rs`, процедурные макросы), поэтому идёт только без сети: `--network=none`, а `oncl-pack build` сам отказывается работать, если в контейнере есть сетевой интерфейс кроме `lo`. Файловая система образа и том `/cargo` только для чтения, каталоги хоста в контейнер на запись не попадают:

```sh
docker run --name oncl-build --network=none --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --cpus 8 --memory 8g --pids-limit 4096 \
  -v oncl-cargo-market-1.2.0:/cargo:ro --mount type=volume,dst=/build -v "$PWD/dist:/in:ro" \
  "$IMAGE" build --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market --out /build/out
docker cp oncl-build:/build/out ./out
docker rm -v oncl-build
ls -l out && sha256sum out/*.onclp
```

Пакет забирается `docker cp` после того, как контейнер завершился, и хешируется на вашей машине. Строкам, которые контейнер напечатал, не доверяйте: их печатает тот же процесс, в котором работал код исходников. В `out` должен оказаться ровно один обычный файл `<id>-<версия>.onclp`. `--mount type=volume,dst=/build` без имени тома даёт новый пустой том, `docker rm -v` удаляет его вместе с контейнером.

`oncl-pack build`:

1. проверяет, что архив канонический, в нём есть `src/<path>/Cargo.toml` и `src/<path>/plugin.toml` и нет `.cargo/config*` по пути к крейту;
2. собирает крейт для `wasm32-unknown-unknown` с `--release --frozen`. Окружение очищено (как после `env -i`), `SOURCE_DATE_EPOCH=315532800`, `CARGO_INCREMENTAL=0`. Профиль `release` дополняется настройками `codegen-units = 1`, `incremental = false`, `debug = false`, `strip = true`, а флаги `-Ccodegen-units=1 -Cdebuginfo=0 -Cstrip=symbols` идут rustc последними и перекрывают и настройки отдельных пакетов в вашем профиле; `opt-level`, `lto` и `panic` остаются вашими. Пути сборки заменяются в модуле постоянными именами: `/cargo`, `/rustc`, `/target`, `/workspace` и `/plugin`;
3. проверяет пакет так же, как демон перед установкой: манифест, версию крейта, ABI модуля, `min_core`;
4. собирает крейт второй раз и сравнивает. Обе сборки идут в одном контейнере, но каждая в своих каталогах `target` и `TMPDIR`, которые она создаёт сама и отказывается найти уже существующими. Если две сборки различаются, пакет не выдаётся: что-то в вашем крейте или его зависимостях собирается неповторяемо. Частые причины — порядок `HashMap` в процедурном макросе и время или случайные данные в `build.rs`.

Хеш и длину пакета, посчитанные на вашей машине, вы подписываете в своей роли. Опция `--jobs N` ограничивает параллельность Cargo; на байты пакета она не влияет.

На 8 ядрах порт `plugins/eot` этого репозитория скачивал зависимости 6 с, а обе сборки в одном контейнере заняли 20 с. Образ без сжатия занимает около 1,5 ГБ.

### 4. Проверка выпуска

Любой может пересобрать опубликованный выпуск и сравнить байты. Из выпуска `pub-<издатель>-<sha256 пакета>` в Releases OpenNCALayer скачайте `<id>-<версия>.src.tar.gz` в текущий каталог, затем: зависимости с сетью, проверка без неё.

```sh
docker volume create oncl-verify-cargo
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v oncl-verify-cargo:/cargo --mount type=volume,dst=/build -v "$PWD:/in:ro" \
  "$IMAGE" fetch --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v oncl-verify-cargo:/cargo:ro --mount type=volume,dst=/build -v "$PWD:/in:ro" \
  "$IMAGE" verify --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market \
  --sha256 <sha256 пакета>
docker volume rm oncl-verify-cargo
```

Вместо `--sha256` можно указать сам пакет: `--package /in/<id>-<версия>.onclp`. Код выхода 0 означает, что пересборка дала те же байты. Иначе команда пишет оба хеша. `verify`, как и `build`, отказывается работать, если в контейнере есть сеть.

### Если не получилось

| Сообщение | Что делать |
|---|---|
| `the archive is not canonical` | Архив сделан не `oncl-pack source` или изменён после. Сделайте его заново командой из шага 1 |
| `the archive has src/….cargo/config…` | Уберите `.cargo/config*` из исходников; нужные настройки перенесите в `Cargo.toml` |
| `the reference build failed (were the crates fetched first…)` | Выполните шаг 2 с тем же томом `/cargo`; проверьте, что `Cargo.lock` в архиве актуален |
| `the network is on` | Запустите `build` или `verify` с `--network=none` |
| `two builds of the same sources differ` | Сборка неповторяема: ищите неустойчивый порядок или время в процедурных макросах и `build.rs` |
| `unpacking the archive (the work directory must be fresh)` | Монтируйте в `/build` новый том на каждый запуск |
| `detected dubious ownership` от git | Передайте переменные `GIT_CONFIG_*` из шага 1 |

## Образ сборщика

Это раздел для владельца проекта.

- Образ собирается из [`xtask/assets/plugin-builder/Dockerfile`](../../xtask/assets/plugin-builder/Dockerfile). Контекст сборки — корень репозитория, `oncl-pack` собирается из того же коммита. Базовый образ закреплён по digest, архивы тулчейна — по sha256 из `channel-rust-<версия>.toml`. Версия Rust в Dockerfile совпадает с `rust-toolchain.toml`, это проверяет тест.
- Публикует образ workflow [`plugin-builder.yml`](../../.github/workflows/plugin-builder.yml), его запускают вручную. Задание `test` без прав на запись собирает образ, дважды собирает в нём порт (тест `image` крейта `oncl-pack`) и сохраняет образ артефактом. Задание `publish` в окружении `plugin-builder` загружает этот образ, отправляет его в ghcr.io с тегом коммита, подписывает аттестацию происхождения и выводит в сводке готовую запись для `publishers/builders.toml`. Кода репозитория в нём не запускается.
- Окружение `plugin-builder` создаётся один раз и пропускает только `main`: запуск с другой ветки на нём останавливается. Через веб-интерфейс: Settings → Environments → New environment `plugin-builder` → Deployment branches and tags → Selected branches and tags → Add `main`. Или командами:

  ```sh
  gh api -X PUT repos/arynyklas/OpenNCALayer/environments/plugin-builder \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
  gh api -X POST repos/arynyklas/OpenNCALayer/environments/plugin-builder/deployment-branch-policies \
    -f name=main -f type=branch
  ```

  Секретов у окружения нет: пакеты пишет `GITHUB_TOKEN` задания.
- Сборщиком образ становится только после PR владельца, который добавляет запись в конец `publishers/builders.toml`. Записи там не меняются и не удаляются, иначе старые выпуски нельзя будет пересобрать. Схему файла описывает `xtask/src/publishers/builders.rs`.
- Собрать и проверить образ локально:

  ```sh
  git archive HEAD | docker build -f xtask/assets/plugin-builder/Dockerfile -t oncl-plugin-builder -
  ONCL_BUILDER_IMAGE=oncl-plugin-builder cargo test -p oncl-pack --test image -- --ignored --nocapture
  ```

  Без `ONCL_BUILDER_IMAGE` тест сам собирает образ из `HEAD`. На машине с 8 ядрами сборка образа занимает около 2 минут, тест — около минуты.
