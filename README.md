# OpenNCALayer

Открытая замена NCALayer. Нужна, чтобы подписывать документы ЭЦП на сайтах: egov.kz, госзакупки, банки, ЭДО. Сайты работают с ней так же, как с оригиналом, менять на них ничего не нужно.

Проект независимый и не связан с НУЦ РК.

## Установка

1. Скачайте установщик для своей системы со страницы [«Загрузка»](https://arynyklas.github.io/OpenNCALayer/download/): Windows (в том числе Windows 7), macOS или Linux.
2. Установите [расширение браузера](docs/user/browser-extension.md). Это самый простой способ, чтобы сайт увидел программу.
3. Откройте сайт и подпишите документ как обычно.

Без расширения тоже можно: выпустите сертификат в меню значка программы → «Сертификат для браузера…» ([инструкция](docs/user/tls.md)).

Подробнее, в том числе как удалить программу: [`docs/user/install.md`](docs/user/install.md).

## Что работает

- Подпись и вход по ключам из файлов `.p12`, `.pfx`, `.jks`.
- Проверка сертификатов НУЦ.
- Плагины сторонних сайтов, перенесённые из оригинала.
- Обновляется сама.

Пока не работает или не проверено:
- шифрования и расшифрования нет;
- токены и удостоверение личности — экспериментально, выключены по умолчанию;
- установщики не подписаны: Windows покажет предупреждение SmartScreen, macOS — Gatekeeper.

Отличия от оригинала: [`docs/user/compatibility.md`](docs/user/compatibility.md).

## Помощь

- Вопросы — в Telegram-чате [t.me/OpenNCALayer](https://t.me/OpenNCALayer).
- Ошибки — в [Issues](https://github.com/arynyklas/OpenNCALayer/issues).
- Уязвимости — только приватно, см. [`SECURITY.md`](SECURITY.md).

## Для разработчиков

Ту же подпись можно использовать без десктопной программы:
- **библиотека для Rust** — [`docs/dev/sdk-overview.md`](docs/dev/sdk-overview.md);
- **командная строка `oncl`** — [`docs/user/cli.md`](docs/user/cli.md);
- **HTTP-сервис `oncl-server`** — [`docs/user/server.md`](docs/user/server.md).

Как собрать и проверить проект: [`docs/dev/development.md`](docs/dev/development.md). Как устроен оригинальный NCALayer: [`docs/original/architecture.md`](docs/original/architecture.md).

## Лицензия

© 2026 Aryn Yklas. [Apache-2.0](LICENSE), см. также [NOTICE](NOTICE).

`web/demo/vendor/ncalayer-client.js` — MIT, см. [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE). Velopack (MIT), бэкенд winit из Slint (LicenseRef-Slint-Royalty-free-2.0), `multer` (MIT), `streebog` и `hmac` (MIT или Apache-2.0) собираются из наших форков с небольшими изменениями; список форков — в [NOTICE](NOTICE).
