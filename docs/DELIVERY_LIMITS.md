# Синхронизация и лимиты ресурсов

Изменения относятся к текущим серверу и клиенту; это не аудит и не ограничение
общего потребления памяти/диска враждебным клиентом. Сделайте резервную копию
базы и профиля перед обновлением.

## Безопасная доставка и старые клиенты

Сервер теперь по умолчанию отвечает 503 на устаревший `GET /messages/sync`,
который помечал сообщения доставленными до записи у получателя. Старые клиенты,
полагающиеся на него, должны быть обновлены. Новый клиент использует
`/messages/sync-safe` и подтверждает сохранённые сообщения через `/messages/ack`.
Для осознанной временной миграции доступен серверный флаг
`ALLOW_DESTRUCTIVE_LEGACY_SYNC=true`, который возвращает старое небезопасное
поведение. Он может приводить к потере сообщений и не рекомендуется. Серверные
и клиентские обновления надо устанавливать согласованно; новый клиент не
переключается на старый endpoint при его отсутствии.

Новый клиент запрашивает до 20 сообщений за страницу, при этом прежнее значение
по умолчанию сервера остаётся 100 для совместимости. Ограничение чтения ответа
24 MiB: слишком большой или повреждённый ответ отклоняется без ACK. Старый сервер,
не поддерживающий параметр `limit`, может вернуть до 100 сообщений; если ответ
превысит предел клиента, синхронизация не продвинется до обновления сервера или
ручного администрирования. На новом сервере можно задавать `limit` от 1 до 100.

## Приём новых личных сообщений

Оба endpoint отправки применяют одинаковые квоты к **неподтверждённым** личным
сообщениям адресата. Значения настраиваются в переменных окружения сервера:

| Переменная | По умолчанию | Назначение |
| --- | ---: | --- |
| `MAX_PENDING_PER_DEVICE` | 1000 | Количество ожидающих сообщений на получающее устройство |
| `MAX_PENDING_PER_SENDER` | 200 | Сколько из них может занять одно отправляющее устройство |
| `MAX_PENDING_BYTES_PER_DEVICE` | 67108864 | Сумма UTF-8 байт ciphertext и подписи ожидающих сообщений |
| `MAX_MESSAGE_PAYLOAD_BYTES` | 1048576 | Максимальная сумма байт ciphertext и подписи одного нового сообщения |
| `MAX_ACTIVE_DEVICES_PER_USER` | 32 | Максимум неотзванных устройств на один аккаунт при входе с нового устройства |
| `MAX_TOTAL_DEVICES_PER_USER` | 256 | Общий предел зарегистрированных устройств аккаунта (включая отозванные) |
| `MAX_GRANTS_PER_FILE` | 200 | Максимум уникальных устройств-получателей, которым можно выдать доступ к одному файлу |
| `RATE_LIMIT_MESSAGE_SEND` | `240/minute` | HTTP rate limit на IP для `/messages/send` и `/messages/send-reliable` |
| `RATE_LIMIT_MESSAGE_SYNC` | `240/minute` | HTTP rate limit на IP для `/messages/sync`, `/messages/sync-safe` и `/messages/ack` |

SQLite `BEGIN IMMEDIATE` сериализует проверку и запись, в том числе при
конкурентных запросах разных процессов, работающих с одной локальной БД. При
заполнении сервер отвечает 429, а не удаляет сообщения; после ACK появляются
свободные места. Идемпотентный повтор уже принятого сообщения остаётся доступен
даже при заполненной очереди, несовпадение содержимого с ID отвергается. Новый
клиент хранит сообщение в очереди и предупреждает о 429; он повторяет отправку.
Внешние ошибки записи/сети по-прежнему могут означать неопределённый результат.

Неподтверждённые ранее сообщения не удаляются при включении ограничений. Если их
уже больше лимита, новые не будут приняты до освобождения места. Предел 1 MiB
может отклонить старые клиенты, отправляющие очень большие payload. Новый клиент
ограничивает текст 512 KiB и дополнительно проверяет размер зашифрованного пакета.

Для `/messages/send`, `/messages/send-reliable` и других не-upload запросов с
методами POST, PUT, PATCH, DELETE сервер ограничивает тело до 2 MiB до разбора,
включая chunked-тела. Для загрузок действуют отдельные потоковые лимиты ниже.
Это может отклонить крупные запросы старых клиентов; ограничение не учитывает
совокупную память, число соединений или медленную передачу. Нужен reverse proxy
с лимитами соединений и таймаутами. Ответ успешной надёжной
отправки ограничен клиентом до 2 MiB: сервер возвращает полное зашифрованное
сообщение даже в подтверждении, поэтому 16 KiB было недостаточно для больших
обычных сообщений. Подтверждения загрузки и выдачи доступа ограничены до 16 KiB. Ошибки валидации этих двух endpoint
теперь возвращают общее сообщение 422 без отражения присланного содержимого.
Ошибки валидации регистрации, входа и смены пароля (`/auth/change-password`)
также не отражают пароли и инвайт-код.
`/messages/ack` принимает до 100 непустых ID длиной до 64 символов; перед
записью он повторно проверяет активность устройства и учётной записи под
SQLite writer lock, чтобы отзыв и подтверждение сериализовались.

Эти квоты применяются к ожидающим сообщениям, а для ограничения роста таблицы
`messages` подтверждённые (`is_delivered=true`) личные сообщения старше
`DELIVERED_MESSAGE_RETENTION_SECONDS` (по умолчанию 604800 с = 7 суток) при
старте сервера и в фоновом цикле (раз в 30 минут) сворачиваются в легковесные
записи `message_idempotency` с SHA-256-дайджестом конверта (хранятся
`IDEMPOTENCY_TOMBSTONE_TTL_SECONDS`, по умолчанию 2592000 с = 30 суток;
неподтверждённые сообщения никогда не затрагиваются). Пока tombstone не истёк,
идемпотентный повтор `/messages/send-reliable` с тем же конвертом эхом возвращает
подтверждение без повторной постановки в очередь, несовпадающий конверт
отвергается с `409`, а курсор `after` в `/messages/sync-safe` продолжает
работать по сохранённому `original_created_at`. После истечения TTL tombstone
слишком старый повтор или курсор больше не распознаются; SQLite не уменьшает
размер файла БД на диске без `VACUUM`, но освобождённые страницы переиспользуются.
Квоты не предотвращают атаки с множества учётных записей,
не применяются к явно включённым небезопасным группам или общему объёму загруженных файлов, не
считают все служебные байты SQLite или HTTP, и не гарантируют пропускную
способность. Защитите публичный сервер лимитами размера HTTP-тела, соединений,
скорости и дисковой квотой на reverse proxy; не удаляйте произвольно доставленные
строки вручную в обход механизма tombstone.

## Клиентское хранилище и медиа

При отсутствии ключа локального хранилища в keyring и наличии истории, `allies.enc`,
`device_identity.enc`, `groups.enc` или файлов очереди новый ключ больше не
создаётся: сохранённые данные не перезаписываются, требуется восстановление
исходного ключа. Контакты и отметки сверки отпечатков сохраняются в
аутентифицированном зашифрованном `allies.enc` с привязкой к имени профиля
(после появления `allies.enc` незашифрованный `allies.json` игнорируется и не
используется как откат; повреждённые файлы не перезаписываются автоматически).
Привязка устройства к серверу дополнительно хранится по профилю в
`device_identity.enc`, чтобы переключение между учётными записями на одном ПК
не теряло `device_id` и не отправляло его на чужой адрес сервера.
Это не защищает от удаления всех файлов и меток, полного отката каталога
профиля, компрометации ОС/keyring или одновременной работы со старой копией
клиента. Восстанавливайте профиль и соответствующий keyring вместе.

Зашифрованное скачиваемое вложение читается потоком с пределом 21 MiB; старые
более крупные файлы не откроются в новом клиенте. Лимит декодера Qt для отдельных
изображений установлен на 64 MiB, но поведение кодеков и совокупное потребление
памяти необходимо проверять на целевых системах. Эти пределы не заменяют анализ
входных файлов, защиту от исчерпания диска и строгую границу памяти процесса.

Тесты включают конкурентное заполнение очереди, повтор при полном лимите,
освобождение места после ACK, ограничения байтов и проверку на потерю keyring;
отдельный сценарий связывает реальную очередь desktop и криптографию NaCl с
серверным TestClient, потерянным ответом и повтором. Это не полноценный GUI,
туннельный, TURN или power-loss end-to-end тест. Экспериментальные ratchet и
prekey не подключены к рабочему протоколу; см. `protocol-evaluation.md`.


## Вложения на сервере

`/files/upload-reliable/{UUID}` заранее записывает в SQLite резервирование UUID
за устройством, до чтения и публикации файла. При прерывании эта привязка
позволяет повторить те же байты только с этого устройства; конкурирующая загрузка
другим устройством получает 409. После завершения добавление записи и удаление
резервирования совершаются одной транзакцией. Авторизация проверяется повторно
под SQLite write lock после загрузки; выдача доступа сериализована с отзывом
устройств и учитывает деактивированные учётные записи.

**Миграция:** `create_all` при старте создаёт новую таблицу
`upload_reservations`; сначала сохраните копии базы и каталога `secure_uploads`,
обновите все серверные процессы и проверьте миграцию на копии. Старая версия
могла оставить файл без строки БД и без привязки к устройству. Такой файл новый
сервер не присвоит автоматически даже при совпадении байтов: он ответит 409 и
потребует ручного расследования. Не запускайте старые и новые процессы совместно
с одной БД/каталогом — старый сервер не соблюдает резервирование.

На устройство по умолчанию допускается 200 **незавершённых** резервирований
(`MAX_INCOMPLETE_UPLOADS_PER_DEVICE`); повтор уже зарезервированного UUID и
завершённые файлы не расходуют новые места. Ошибка, обрыв или слишком большая
загрузка могут оставить резервирование. Зависшие резервирования, для которых
в БД нет `FileRecord` и на диске **отсутствует** опубликованный блоб, безопасно
очищаются по истечении `UPLOAD_RESERVATION_TTL_SECONDS` (по умолчанию 86400 с =
24 часа) при старте сервера и лениво под `BEGIN IMMEDIATE` при достижении
лимита, а также могут быть явно отменены самим устройством-владельцем через
`DELETE /files/upload-reliable/{UUID}`. Если же блоб уже опубликован на диск
(`os.link` прошёл до падения процесса, но запись `FileRecord` не закоммичена),
такое резервирование автоматически **не** удаляется и не отменяется через
`DELETE`, сохраняя защиту от присвоения файла другим устройством до повтора
загрузки владельцем или ручного администрирования.
Администратору следует остановить все процессы и клиенты записи, сделать резервную
копию, сверить незавершённые UUID с клиентскими очередями и файлами и только затем
вручную разбирать действительно брошенные записи и файлы. Это не готовая миграция
или автоматический garbage collector.

Для raw upload действует предел тела 100 MiB, для старого multipart — 101 MiB,
включая заголовки формы; multipart принимает один файл и никаких дополнительных
полей. Проверка применяется и к chunked-телам. Старый multipart сначала может
использовать временный файл на диске; одновременно возможны временная и постоянная
копия. После авторизации на каждый процесс сервера допускается до 8 одновременных
загрузок обоих типов (`MAX_CONCURRENT_UPLOADS_PER_PROCESS`); лишние получают 503
и `Retry-After: 5` до создания резервирования или чтения тела. Desktop хранит
задание и повторяет позже, обычно не раньше 5 минут. Проверка хеша имеет отдельный
пул из 2 потоков и до 8 активных/ожидающих заданий; отменённый запрос не
освобождает место до завершения работающей проверки. Это пределы **на процесс**,
не общие на сервер. Долго загружающий клиент может занять место; на уровне аккаунта введены квоты
хранимых завершённых вложений (`MAX_STORED_FILES_PER_USER`, по умолчанию 2000
файлов, и `MAX_STORED_BYTES_PER_USER`, по умолчанию 2 ГиБ; идемпотентный повтор
уже сохранённого `file_id` остаётся доступен) и очистка по сроку хранения
(`UPLOADED_FILE_RETENTION_SECONDS`, по умолчанию 30 суток; блоб удаляется с
диска только после `commit` удаления `FileRecord`), однако суммарный диск со
множества учётных записей и число TCP-соединений всё равно не ограничены. Нужны
лимиты proxy, файловой системы и времени загрузки. Жёсткий сбой может оставить
временные или зарезервированные файлы. Гарантия после отключения питания,
включая синхронизацию каталога, не проверена. Старая multipart-загрузка теперь
синхронизирует файл перед записью в БД и сохраняет его при неопределённом
результате commit: файл может оказаться бесхозным и потребовать ручной проверки,
но не удаляется, если транзакция уже успела завершиться. Из-за потерянного ответа
старый клиент не знает ID и при повторе может создать дубликат. Сверка хеша уже
опубликованного reliable-файла выполняется вне event loop и читает не больше
заявленного размера плюс один байт; запись и fsync всё ещё могут блокировать
loop, а общая межпроцессная конкурентность и диск отдельно не ограничены.

Локальные зашифрованные записи очереди ограничены 8 MiB каждая. Непрочитанная
запись не удаляется и временно пропускается, чтобы остальные могли отправиться;
для восстановления может потребоваться исходный keyring и резервная копия.
Перед восстановлением истории исходящая запись сверяется с подписанным
сообщением: ID, текст или метаданные вложения и поля ответа должны совпадать.
Неизвестные поля записи не отправляются серверу: несовместимое задание остаётся
в очереди. Старые задания с локальной историей, но без ID в подписанном тексте,
теперь также остаются в очереди для ручного восстановления; старые записи без
локальной истории по-прежнему могут отправляться. После восстановления истории
повторно сверяются учётная запись, токен и получатель. Задание вложения перед загрузкой и повторно после подготовки
также сверяется с подписью и адресатом шифротекста, ID файла, ключом и ID
сообщения в локальной истории; смена сессии до ответа загрузки или выдачи
доступа не удаляет задание. Перед отправкой worker считывает не более 21 MiB
ciphertext плюс один байт и проверяет размер, SHA-256 и аутентичность SecretBox
ключом из подписанного сообщения. В сеть передаётся тот же снимок ciphertext,
поэтому последующее изменение файла не заменяет отправляемые байты. После запуска
worker смена сессии не отменяет его проверку или уже начатую загрузку со старым
токеном; выдача доступа и дальнейшая отправка перепроверяют контекст. Ошибочные и
старые задания больше 21 MiB сохраняются и не отправляются; этот предел совпадает
с ограничением скачивания. Проверка создаёт временные копии ciphertext и plaintext
в RAM, но не пишет plaintext на диск; безопасное стирание памяти Python не
гарантируется. История могла быть записана до ошибки проверки. Ошибка подготовки
отдельного задания не блокирует следующие; при общей ошибке keyring или доступа
к очереди обработка ждёт повтора. Запоздалые повторные завершения старого worker
не освобождают и не заменяют текущий worker очереди.
При отмене очереди сначала проверяются все выбранные пути; сбой файловой системы
во время удаления всё ещё может привести к частичному результату.
Немигрированная монолитная история чата целиком считывается и переписывается
при изменении. Доступна отдельная экспериментальная миграция по одному чату в
[построчное хранилище](history-store.md); автоматического перехода нет. Общая
граница RAM пока не гарантируется.

### Desktop media memory and cache

- At most two attachment downloads run at once, with at most 100 waiting in the
  in-memory queue. Further attachments show a retry link; changing the chat
  discards waiting jobs, and completions from an old view/account are ignored.
  Closing the application is temporarily refused while downloads are running:
  the underlying blocking HTTP request is not cancellable and a slow peer may
  delay shutdown. These limits are per desktop window, not a global RAM cap.
- Voice messages are loaded/downloaded when played rather than all at once;
  waveform generation samples bounded windows instead of expanding all samples
  into Python integers. Incoming duration metadata is validated. Outgoing voice
  bubbles and decoded image widgets can still retain significant memory.
  Recording is capped at two minutes of mono PCM. A stuck microphone blocks a
  new recording and may block application close; a timed-out recording is not
  sent. Stale recording signals cannot cancel a newer recording. Before opening
  an audio output stream, decrypted WAV input is capped at 21 MiB and checked
  for bounded channels, sample width/rate and complete PCM frames. Unsupported
  or malformed legacy audio can no longer be played automatically.
- Playback uses at most one native audio thread and one replaceable pending
  request. Repeated seek/play operations invalidate older generations, and
  audio callbacks are delivered to the GUI through Qt signals without touching
  widgets in the playback thread. Leaving the page or pausing invalidates pending
  downloads as well. Closing refuses while an audio operation is still blocked;
  the driver cannot be forcibly interrupted safely. Simulated drivers and QCore
  tests cover these paths, not full GUI, physical audio or all target OSes.
- Voice cache v2 is scoped to account, server, chat, message, file and file key;
  cached images are likewise scoped to the current account/chat and file key.
  The old unscoped voice files are left untouched and are **not automatically
  used or migrated** because their chat/profile cannot be safely established.
  Voices may therefore need to be downloaded again, and old offline-only cache
  entries require manual recovery with the original version and keyring. Keep a
  backup; explicit cache clearing also removes legacy entries. Missing/wrong
  cache keys or corrupt entries are not deleted or overwritten automatically.
  Cache files are replaced atomically after flushing, but directory metadata is
  not fsynced, so power-loss durability is not guaranteed. Multi-process cache
  key initialization is not coordinated.
- History and search render at most 25 messages at a time with older/newer
  navigation. The selected page can be marked read, not the entire chat; new
  messages received while viewing an older page stay unread. The view is anchored
  against newly appended messages; deletions can shift page boundaries. A reply
  can navigate to its original message. Search only exposes user-visible text,
  not embedded attachment keys. When the window is activated, displayed unread
  messages on the selected personal page can be marked read without rebuilding
  bubbles; hidden/search/group pages are excluded. Read receipts remain
  best-effort, not durable. A receipt for a newly displayed verified message is
  addressed to the actual verified sender device. Page-based receipts target the
  currently selected verified device, but history lacks the original sender-device
  identity, so multi-device routing may still be wrong. If the selected device is
  unverified, no receipt is sent. A receipt carries at most 1024 IDs; larger inbound
  receipts are left pending rather than partially applied. Read status is saved
  before the best-effort send, so a dropped receipt is not retried automatically.
- UI paging alone does **not** solve large-history memory usage for unmigrated
  chats: their legacy encrypted file is still decrypted in full and rewritten on
  every update. An explicit experimental per-chat SQLite migration is described
  in [history-store.md](history-store.md), including its backup, lock, rollback
  and GUI-latency limitations. Images are still downloaded automatically for the
  visible page and may retain decoded pixels; preview/original display dimensions
  are bounded to 320/1200 pixels per axis, with the 64 MiB Qt allocation limit.
  Lazy images, limits on every outgoing attachment path and an aggregate RAM
  budget remain necessary.
- Unreadable history is explicitly reported rather than shown as an empty chat.
  Chat identifiers containing characters outside ASCII letters, digits, `_` and
  `-` are now rejected instead of silently mapping to another filename. Legacy
  histories with such identifiers need manual recovery; no files are renamed or
  deleted automatically. Profile history is still keyed by username, not server;
  multiple servers sharing a username and simultaneous application processes
  are not safely isolated by this format.
- Attachment downloads reject non-canonical UUIDv4 identifiers before making a
  request and do not follow HTTP redirects; the configured tunnel/server URL
  must therefore point directly to the API. Incoming file keys must be canonical
  32-byte Base64. Malformed/legacy nonconforming attachment metadata will not
  be downloaded automatically; this is not a deletion of the history or files.

### Desktop instance and network boundaries

- The standard `run_desktop.py` entry point acquires a Qt lock in the shared
  `.max1m` directory before loading the application. A second updated instance
  using the same directory refuses to start. A Linux subprocess test covers
  contention and recovery after an abrupt process exit. Old client versions,
  scripts importing storage directly, deleting the lock file while in use,
  network filesystems, and external keyring changes bypass or may defeat
  this guard. Calls through `SecureStorage` within one process now serialize by
  profile, but direct file access, other queues and older code are not fully
  coordinated. It is not a transactional file format or a substitute for backups;
  Windows/macOS behavior has not been tested here.
- Contact lookup responses are streamed with a 1 MiB cap and at most 256 devices;
  group list responses are capped at 4 MiB and 1000 groups. Invalid results are
  rejected rather than partially applied. An account exceeding these limits needs
  server-side cleanup or a future paginated API. Group membership/key retrieval
  and group message sync are not started by the disabled legacy group client;
  group messages are not acknowledged and remain on the server.
- Contact lookup, personal sync/ACK, reliable send/upload/grant, attachment
  downloads and group list/leave/delete do not follow redirects. Configure the
  final tunnel URL directly. Request timeouts are per socket operation, not a
  strict wall-clock limit; a slow peer can still delay completion.
- Deletion/leave and server group-deletion notices no longer delete local group
  history. Locally known groups and pre-existing `group_<id>` histories are
  recorded in an encrypted per-profile `groups.enc` index and restored across
  restart as read-only `(неактивна)` cards whenever the server no longer returns
  them (or before group fetch completes). Corrupt `groups.enc` files are never
  silently overwritten. Explicit “clear history” still deletes history after
  confirmation, while keeping any archived metadata entry unless removed manually.
  A confirmed server-side group deletion can permanently delete server data; no
  rollback is claimed.
- Newly generated local-storage and voice-cache keys are read back from keyring
  before durable encryption. The voice cache also rechecks its cached key before
  writes; a missing or changed key prevents new cache entries while already-open
  data can still be read in the current process. This is not atomic with keyring
  changes by external programs and cannot recover a key that has been lost.

### Server WebSocket backpressure

- Each connected device has at most 16 active/waiting server sends, serialized
  per socket. Waiting for a send slot and an actual send each time out after
  five seconds; a failed, cancelled or timed-out active send disconnects the
  affected socket. Replacing a connection cannot remove its newer replacement.
  When the queue is full a live notification is dropped: reliable personal
  messages remain in SQLite for safe sync/ACK, but transient call and group
  events can be lost. The desktop normally retries sync every 30 seconds while
  connected; this is not a real-time delivery guarantee. Limits are per process
  and connection, not global connection/RAM limits; multi-process routing, slow
  networks and sustained overload need production testing.

### Desktop event and acknowledgement backpressure

- At most 16 application WebSocket events are outstanding for the GUI. When
  they are not consumed, the worker pauses reads and the WebSocket library and
  TCP apply backpressure; its existing 2 MiB frame/message and `max_queue=8`
  limits still apply. GUI processing returns a slot even on an exception, and
  events from an old account/worker are discarded. This is not a global memory
  limit: JSON decoding, socket buffers, status events, histories and other GUI
  work also consume memory. A stalled GUI or saturated connection can delay
  signaling or cause a disconnect; transient call events are not durably queued.
- At most 32 outgoing WebSocket sends may be scheduled at once, each no more
  than 128 KiB encoded. A full queue or oversized signal is rejected locally;
  signaling has no delivery acknowledgement or automatic retry, so calls may
  fail under overload. A successful scheduling result is not proof of delivery.
- Transient personal messages (typing, read and delete notices) require a
  verified selected recipient, and are capped at 16 active HTTP workers per
  screen. When saturated they are dropped, not queued or retried. They capture
  account and owner key and recheck trust after encryption. Their HTTP requests
  reject redirects and bound response size, but an already started request cannot
  be recalled after a context change. A missing delete notice does not undo a
  local deletion and does not guarantee remote deletion.
- Personal sync rejects a page with more than the requested 20 records and
  uses at most one ACK worker, waiting for it before requesting the next page.
  A processing exception leaves that record pending and does not stop independent
  records on the same page. A page containing repeated valid IDs is rejected
  without processing or acknowledgement; an incompatible server can therefore
  stall that scan. Failed ACKs are retried during a later scan; only messages verified and saved
  locally are acknowledged. The account and screen are checked before and after
  each page callback; if they change, later messages are not processed and the
  page is not acknowledged or advanced. The incoming handler also rechecks the
  session, local public key and sender trust after decryption and storage, before
  updating the view or emitting success. This cannot roll back a local write or
  read flag that already happened inside a blocking callback, nor detect a
  session changing away and back to an identical context during that callback. Oversized IDs, ciphertexts and signatures are not
  processed or acknowledged. Invalid older/server-provided records may remain
  pending and require recovery rather than being silently deleted. Both storage
  modes reject conflicting message IDs; new legacy tombstones preserve a keyed
  identity for matching retries, while older tombstones without it cannot be
  verified. Malformed text, caption, reply and ID types are rejected before
  history writes. Per-operation
  socket timeouts do not guarantee a wall-clock deadline for a slow peer.
- Closing cancels the history-page worker and refuses to destroy it if it has
  not stopped promptly. It also waits for the WebSocket worker and refuses to
  close while tracked authentication, contact lookup, network, sync or ACK
  threads are active; a stalled request may require waiting and retrying close. QCoreApplication and simulated network tests exercise these boundaries;
  full GUI, real calls and overload behavior on real networks remain unverified.

### Isolated delivery and upload concurrency smoke test

From `max1m_backend`, with backend test dependencies installed, run either:

```sh
python tools/delivery_load_smoke.py --messages 400 --workers 16 --payload-bytes 1024
python tools/delivery_load_smoke.py --transport loopback --messages 400 --workers 16 --payload-bytes 1024
```

The script creates and removes its own temporary SQLite database, overrides the
caller's database path and signing secret before importing the app, and never
contacts a remote server. The default uses in-process TestClient; loopback runs
Uvicorn on an ephemeral `127.0.0.1` port and makes real local HTTP connections,
ignoring proxy environment settings. Both use synthetic message and file bytes
with the rate limiter intentionally disabled. They check parallel reliable
sends, identical retries, non-destructive concurrent sync, foreign ACK isolation,
page-by-page double ACK, concurrent quota saturation/recovery, and parallel
upload, grant and download including retries and conflicts. Loopback additionally
closes a TCP connection after sending a request without reading its response,
then verifies idempotent retry and ACK. Tests verify temporary isolation and
cleanup. Inputs are bounded; no user data is loaded or modified.

The printed timing is a **local diagnostic**, not a production throughput or
latency guarantee. Loopback is not representative of internet connections. The
script does not test NaCl, GUI, TLS, proxies, multiple server processes,
persistent disks under load, real clients, slow networks, packet loss or
long-duration resource exhaustion. Keep real-network/multi-process load and
failure tests on the release checklist.

### Isolated process-crash recovery smoke test (Linux)

Run `python tools/restart_recovery_smoke.py` from `max1m_backend`. It starts a
child server on an ephemeral loopback socket with its own temporary database,
secret and synthetic devices. It verifies two committed pending messages,
including a send whose response was never read, then kills that server while a
raw upload has an established reservation and an incomplete body. On restart
it checks safe sync, message retry, foreign-device ACK isolation, repeated ACK,
reservation ownership, upload retry, access grant and downloaded bytes. It also
kills synthetic child servers at two precisely injected points: after publishing
the blob but before the database commit, and after commit but before the HTTP
response. Each restart checks identical retry, conflicting bytes and foreign
device rejection. Fault injection exists only in the smoke child, not the app.
The child uses a Linux parent-death signal; normal cleanup removes the temporary
profile. The tool cannot accept an existing database or remote server address.

A staging file remained after the forced crash in this test. Production cleanup
of such files and abandoned reservations is **not implemented**: deleting them
without coordinating active uploads is unsafe. For aggregate, read-only diagnosis
of a detached offline snapshot, see `docs/upload-recovery-audit.md`; its report
is not an authorization to delete or release anything. This smoke checks process death,
not power failure, storage-controller behavior, directory fsync, multiple
workers or network failures; it cannot establish power-loss durability.

### Outgoing confirmation checks

The desktop reliable-send worker retains the encrypted queue entry unless the
HTTP success response echoes the queued UUID, ciphertext and signature and the
expected sending-device ID. A malformed or mismatched response is treated as an
uncertain outcome, not proof of failure: the server may already have committed
it, so retry uses the same UUID. Updated servers also echo the recipient device
ID on reliable sends, which updated clients check when present. To preserve
compatibility, older server responses without this field are accepted, so their
recipient is not verified; stripping the field also bypasses this extra check.
Safe-sync responses retain their old shape. A malicious server can echo any
values without actually storing or delivering a
message, so this check is not cryptographic proof of delivery. A normal success
only means the server reported acceptance, not that the peer read it.

The desktop's reliable upload and grant API also validate canonical UUIDv4 file
IDs (and recipient device IDs / group IDs in worker URLs) before constructing
URLs, disable HTTP redirects (`allow_redirects=False`), bound JSON response
bodies across group and upload workers, and block remote cleartext `http://` /
`ws://` server URLs across all `APIClient` methods and `WebSocketWorker` by
default (allowing `http://` only for loopback `127.0.0.1`, `localhost`, `[::1]`
unless `MAX1M_ALLOW_INSECURE_HTTP=1`). Own-device listings (`GET /auth/devices`)
verify the active device's `public_key` when pinned and recompute canonical
Ed25519 SHA-256 fingerprints locally rather than trusting server-claimed
`fingerprint` strings. Reliable uploads reject empty or over-21 MiB
ciphertexts before issuing HTTP; older incompatible
jobs are retained locally. On the relay server, incoming WebSocket signaling
frames (and decrypted client `call_envelope` payloads) reject non-finite JSON
numbers (`NaN`/`Infinity`) and deeply nested structures (`MAX_RELAY_JSON_DEPTH = 16`)
before queueing/processing. Rate limiting resolves client IPs from
`X-Forwarded-For` / `X-Real-IP` only when the peer socket matches
`TRUSTED_PROXY_IPS` (default empty), `/messages/sync-safe` and `/groups/sync-safe`
validate `after` cursors and honor bounded `limit` (`1..100`), and `GET /files/{id}`
plus `POST /files/{id}/grant` enforce `UPLOADED_FILE_RETENTION_SECONDS`
synchronously at read/grant time alongside `MAX_GRANTS_PER_FILE`. On the desktop
client, decrypted peer chat payloads and inner WebRTC `SignalCrypto` messages
reject `NaN`/`Infinity`, extreme JSON nesting (`RecursionError` / depth `> 16`),
and oversized text/caption/SDP/ICE fields cleanly without crashing audio or
history parsing.

### Call ICE / TURN and relay-only limits

`MAX1M_STUN_URLS`, `MAX1M_TURN_URL` / `MAX1M_TURN_URLS`, `MAX1M_TURN_USERNAME`,
`MAX1M_TURN_PASSWORD` and `MAX1M_ICE_RELAY_ONLY=1` are validated fail-closed
before opening the microphone. URI schemes ignored by `aiortc` (`stuns:` and
`turns:` over UDP) are rejected instead of silently falling back. Note that
`aiortc` 1.14 uses only the first compatible STUN and first compatible TURN URI
from the configured list per peer connection rather than racing multiple TURN
transports simultaneously. When `MAX1M_ICE_RELAY_ONLY=1` is set, STUN is omitted,
`aioice` uses `TransportPolicy.RELAY`, and non-relay candidates are stripped from
SDP and trickle ICE. A local loopback RFC 5766 UDP TURN test exercises two real
`aiortc` peers in relay-only mode, but real `coturn` deployments, internet NATs,
VPN/tunnels and physical audio hardware on target OSes still require end-to-end
testing. Screen sharing uses a separate `RTCPeerConnection` and event loop
(`ScreenPeerSession`, `channel="screen"`) with single-slot latest-frame capture
and the same `MAX1M_ICE_RELAY_ONLY` / TURN policy as voice so video encoding
never blocks the 20 ms voice playback/capture path (`MAX_PLAYBACK_FRAMES = 4`,
80 ms ceiling). Protected group chats (`/groups/v2/*`) enforce `MAX_PENDING_PER_DEVICE`
and `MAX_MESSAGE_PAYLOAD_BYTES` on the relay, verify Ed25519 signatures on both
relay and recipients, bound out-of-order skipped symmetric ratchet keys to
`MAX_SKIP = 256` per sender chain, and retain up to `MAX_KEY_HISTORY_PER_SENDER = 8`
epoch keys in `group_keys.enc` for delayed offline decryption.

In addition to static environment variables, the desktop client fetches
ephemeral `HMAC-SHA1` `coturn` credentials from `GET /calls/ice-config`
(`CALL_STUN_URLS`, `CALL_TURN_URLS`, `CALL_TURN_SHARED_SECRET`,
`CALL_TURN_CREDENTIAL_TTL_SECONDS`) — including `turns:<host>:443?transport=tcp`
for reliable traversal through corporate firewalls and DPI/ТСПУ without VPN —
and provides an encrypted UI toggle («Скрывать мой IP при звонках (Relay-Only)»)
that enforces `TransportPolicy.RELAY` and `filter_relay_sdp` across 1-on-1 calls,
screen sharing, and 2–8 participant group voice rooms (`MAX_GROUP_VOICE_PEERS = 8`,
RAM-only server presence with automatic eviction on WebSocket disconnect).
Personal 1-on-1 chats automatically upgrade verified peers to X3DH + Signal
Double Ratchet (`DR_WIRE_PREFIX = "TTFEUjAx"`, `MAX_SKIP = 256`, two-phase
crash-safe `seen_incoming` staging in `ratchet_v1.sqlite3`) while preserving
compatibility with queued legacy `Box` envelopes during transition.

