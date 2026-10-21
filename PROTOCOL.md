# AlienMode crypt5, envelope v1

`crypt5` — имя собственного формата, не формат Happ и не рейтинг криптостойкости.
Собственная упаковка использует стандартные примитивы CryptoKit / Node crypto.

URI: `alienmode://crypt5/<kid>.<wire>`.
`kid` = `am-2026-01`; `wire` = canonical unpadded Base64URL, без query/fragment, ASCII.
Максимум URI — 65536 UTF-8 байт; неизвестные kid/версии отклоняются без сетевого fallback.

Публичный ключ получателя: 32 raw bytes X25519, Base64URL в `recipient.json`.
Генератор создаёт новую эфемерную пару X25519 и новый случайный nonce для каждой ссылки.

1. `context = UTF8("alienmode://crypt5/" + kid)`.
2. `shared = X25519(ephemeralPrivate, recipientPublic)`.
3. `key = HKDF-SHA256(shared, salt=UTF8("AlienMode crypt5 v1"), info=context, length=32)`.
4. `plaintext = UTF8(JSON)` вида `{"v":1,"url":"https://…","title":"…"}`; title опционален.
5. `AAD = context || ephemeralPublicRaw`.
6. ChaCha20-Poly1305 с ключом 32 байта, nonce 12 байт, тегом 16 байт.
7. `wire = ephemeralPublicRaw[32] || nonce[12] || ciphertext || tag[16]`.

Декодер сначала проверяет границы, kid и canonical Base64URL, затем AEAD, затем версию JSON,
HTTPS URL без userinfo, длину/символы названия. URL fragment используется только как резервное
название и удаляется перед HTTP-запросом. Декодер не исполняет JSON как Xray-конфигурацию.
Ссылка запускает только импорт/загрузку подписки; подключения к VPN без нажатия пользователя нет.

AEAD обнаруживает повреждение данных; оно не удостоверяет личность провайдера.
Протокол не обеспечивает forward secrecy при извлечении общего ключа из приложения.
Ключ клиента намеренно отсутствует в ProviderTools. Не добавляйте туда исходники клиента или vault.
