# Дорожная карта и состояние работ

Дополнительные ограничения доставки, совместимости и ресурсов: [DELIVERY_LIMITS.md](DELIVERY_LIMITS.md).

Дополнительно укреплены загрузка вложений (резервирование владельца UUID до
публикации, повторная проверка отзыва, ограничения потоков), обработка
повреждённых записей локальной очереди и запрет старого screen relay на клиенте.
Проверка ответов исправлена для сообщений, которые сервер возвращает целиком.
Добавлены изоляция поколений звонков и локальная aiortc loopback-проверка;
закрыта автоматическая перезапись ключа устройства при повторной регистрации,
добавлена сверка локального ключа с ответом обновлённого сервера при входе;
условия установки desktop описаны в [desktop-setup.md](desktop-setup.md).
Очередь событий WebSocket и исходящих сигналов ограничена, ACK выполняется по
одному до перехода к следующей странице; это не гарантия доставки сигналов звонка.
Ограничения и порядок обновления описаны в документе выше.

Статус отражает реализованные изменения и выполненные проверки, а не заключение
независимого аудита. Пункты 1–2 реализованы в указанном ниже объёме; пункты 3–6 не выполнены.

1. **Проверка получателя при повторной отправке из очереди — реализовано.**
   Перед каждым сетевым повтором клиент находит уникальное устройство контакта,
   требует вручную подтверждённый отпечаток, проверяет собственную подпись и
   расшифровывает пакет локально ключом этого устройства. Это также работает для
   старых записей без локальных метаданных: если текущий ключ отличается от
   исходного, отправка блокируется. Заблокированные записи не удаляются и не
   мешают обработке остальных. В меню личного чата можно сверить ключ или после
   явного подтверждения отменить все ожидающие записи очереди сообщений либо
   отдельной очереди загрузки вложений данной учётной записи и сервера (с
   попыткой отмены серверных броней загрузки). Удаление конкретного сообщения в
   чате отменяет связанные с ним локальные задания `outbox`/`attachment_outbox`
   и не отправляет `delete_msg` при удалении входящего сообщения собеседника или
   сообщения, которое ни разу не пыталось уйти в сеть (`_send_attempted=false`).
   Отмена не отзывает сообщение, которое сервер уже принял при потерянном ответе;
   отмена очереди без удаления сообщения сохраняет запись истории. Если ключ изменился, прежний пакет автоматически не
   перешифровывается: это могло бы создать дубликат или адресовать текст не тому.
   Проверены unit и callback-тесты, GUI end-to-end не проверен.
2. **Входящие и проверка устройств — реализовано с ограничениями.** Входящий
   пакет принимается только от единственного локально известного устройства с
   отпечатком, вручную сверенным для этой учётной записи, сервера и устройства,
   после проверки подписи и расшифровки. Неизвестные/непроверенные/ошибочные
   пакеты и ошибки локальной записи не подтверждаются серверу. После сверки
   запускается повторное сканирование. В заголовке чата — число проверенных
   устройств и (при нескольких устройствах у контакта) индикация активного
   целевого устройства; при открытии чата клиент автоматически отдаёт приоритет
   проверенному устройству вместо слепого переключения на последнее непроверенное
   и не падает при пустом списке устройств, а из меню чата можно явно выбрать
   активное устройство собеседника (с сохранением проверенного
   `preferred_device_id` в `allies.enc`) или сверить любое устройство по полному
   ID. Поиск позволяет явно добавить новые устройства без доверия, но не заменять или
   удалять старые ключи. Серверные отметки доверия игнорируются. Старые отметки
   без привязки к серверу и своему устройству требуют повторной сверки; это
   также временно блокирует исходящую очередь. Уведомление об отклонённых
   пакетах не раскрывает, какое именно устройство прислало пакет. Старые записи
   истории не подтверждаются задним числом; надёжный перенос/ротация ключей не
   реализованы. Команды удаления могут менять только входящие сообщения контакта;
   неизвестный ID остаётся на сервере для повтора. GUI end-to-end не проверен.
3. **Личные сессии с проверенным ratchet-протоколом — частично, не выполнено.**
   В изолированной [пробе X3DH + Double Ratchet](../experiments/ratchet-probe/README.md)
   проверены обмен, повтор, перезапуск и отказные случаи. Найдены блокирующие
   вопросы порядка доставки и расходования prekey до проверки первого ciphertext.
   Добавлен выключенный по умолчанию экспериментальный серверный API одноразовых
   публичных prekey с идемпотентным конкурентным claim и опциональной серверной
   проверкой подписи Ed25519 над `signed_prekey` (`verify_signature=true` или
   `REQUIRE_SIGNED_PREKEY_VERIFICATION=true`). Отдельный SQLite-прототип
   проверяет совместную транзакцию состояния, истории и очереди с настоящей
   библиотекой, но в клиент не подключён. Добавлены лимиты claim одноразовых
   prekey на одно запрашивающее устройство и аккаунт, но это не production-хранилище:
   нет защиты от отката/копий старых ключей и истощения со множества аккаунтов. Остались
   выбор и аудит библиотеки, end-to-end интеграция, устойчивое хранение с реальным
   управлением ключами, миграция, проверки на целевых ОС и отказные испытания;
   не заявлять совместимость с Signal без аудита.
4. **Защищённые группы — не выполнено.** Рабочая интеграция MLS, проверка identity
   и membership, добавление и удаление участников, offline/restart, согласование
   commit и тесты утраты доступа удалённого участника отсутствуют. До этого
   групповые операции заблокированы. Дополнительно старый разрушительный
   `/groups/sync` теперь заблокирован в настройках сервера по умолчанию: старый
   клиент получает 503 вместо скрытого подтверждения входящих. В явно небезопасном
   режиме миграции старое поведение остаётся доступным.
5. **Звонки — частичное укрепление, не выполнено.** Сигналы привязаны к снимку
   единственного локального устройства и его проверенного ключа; проверка
   повторяется во время звонка. Неоднозначный ID, изменение ключа/аккаунта или
   снятие доверия блокируют сигналы и приводят к запросу завершения звонка.
   Ошибка настройки или создания сессии закрывает начатый аудиоввод; события
   состояния передаются в GUI через Qt-сигнал, громкость собеседника реально
   применяется к входящему потоку, ранние trickle-ICE кандидаты буферизуются до
   установки remote SDP, а отсутствие аудиодрайвера на старте не роняет клиент.
   Поддержаны список TURN URI и строгий режим `MAX1M_ICE_RELAY_ONLY=1` (без
   `host`/`srflx` кандидатов и без обращения к STUN). В локальном тесте два
   реальных `aiortc` peer соединяются через тестовый UDP TURN-сервер в режиме
   relay-only на loopback. Ещё нужны испытания реальных устройств и внешнего
   `coturn` через интернет, NAT и туннели, а также проверка на целевых ОС.
6. **Эксплуатация и аудит.** Миграция старых клиентов, ревизия ранее попавших в
   Git секретов и данных, зависимости и сборки, пределы ресурсов и независимый
   аудит. Это обязательная завершающая проверка, а не обещание отсутствия ошибок.

### Media follow-up

Desktop now bounds simultaneous attachment downloads (2 active, 100 queued),
provides retry for overflow/failure, ignores stale view/account completions,
loads received/history voice on demand and samples waveforms with bounded
chunks. Voice cache entries use scoped v2 identities and atomic replacement;
legacy/unreadable data is preserved rather than silently deleted. History and
search now render 25 messages per page, while unreadable files are reported and
kept intact; search does not reveal embedded file keys. This does not bound the
monolithic history file, decoded images or total RAM. GUI, physical audio and
long-running tunnel behavior still require end-to-end tests.
See `DELIVERY_LIMITS.md` for migration and shutdown caveats.

### Row-oriented history (opt-in, experimental)

The desktop now supports explicit per-chat migration into encrypted SQLite while
retaining the legacy file and refusing to fall back when the catalog, DB or
backup conflicts. The manual command takes the updated desktop's process lock;
old clients are not covered. Migration, crash/resume, catalog/source corruption,
read/delete, paging and verified-delivery callback tests are included. Unmigrated
chats still use monolithic JSON. The feature remains experimental: page scans
now run in a cancellable GUI worker with per-profile in-process revision checks,
and reply lookup uses the same cancellable worker. Previews and writes may
still block the GUI. Legacy backups and
key material must be preserved; full GUI, power-failure and multi-OS tests have
not been done. Calls through `SecureStorage` serialize writes per profile within
one process, and 1024-ID read receipts are atomic. Window activation and returning
from settings mark displayed unread personal messages without rebuilding media. See [history-store.md](history-store.md) for the command and limitations.

### Transient personal-message follow-up

User-initiated deletion commands (`delete_msg`) are now queued durably through
the encrypted personal `outbox` and `/messages/send-reliable`, verified
fail-closed by `outbox_policy.verify_queued_recipient` before every retry.
Typing and page-based read receipts (`read_ack`) use the selected verified
device rather than an arbitrary last device, rechecking account, owner key and
trust before starting a worker, with a per-screen cap of 16 workers and bounded,
non-redirecting HTTP responses so passive history reads do not fill the durable
outbox. Those transient read notices remain best-effort and can be dropped under
load or network failure; page-based receipts cannot determine the original
sender device from old history.

### History replay follow-up

Both legacy and experimental row history reject a conflicting message ID
instead of acknowledging different content. New legacy tombstones retain a
keyed identity, including across explicit copy migration, so identical retries
remain idempotent. Earlier tombstones without an identity are preserved but
cannot be matched safely and need a recovery workflow. Incoming malformed
text, caption, reply and ID fields are rejected before history mutation. These
checks do not protect against old clients, rollback or external key changes.

### Storage and group-event follow-up

The standard desktop entry point now prevents two updated processes from using the
same storage directory concurrently (tested with Linux subprocesses only). Group
delete/leave responses are bound to the initiating account and group, and neither
those responses nor a server deletion notice erase local history. Legacy group
key-fetch fan-out and group sync are not started while the group receiver is
unavailable. Archived/left/deleted groups and pre-existing local `group_<id>`
histories are now restored across restart as read-only archived cards backed by
an encrypted per-profile `groups.enc` index without modifying history files.
Contact and group-list responses are bounded; see `DELIVERY_LIMITS.md` for
compatibility, redirects, process-lock and recovery limitations.

### Queue and incoming-context follow-up

Queued sends pin the account and recheck the verified recipient after local
history preparation. Before restoring history, text, message ID, reply and
attachment metadata must match the signed ciphertext; unknown record fields are
rejected without sending or deleting the record. Legacy records with local
history but no signed message ID remain blocked for manual recovery; legacy
records without local history remain supported. Attachment jobs also verify that their signed encrypted
payload belongs to the pinned contact and references the queued file and local
message ID before upload. An upload worker authenticates a bounded ciphertext
snapshot using the signed message's file key and sends those exact bytes; it
preserves failed or oversized jobs rather than deleting them. The check briefly
allocates plaintext in RAM and does not guarantee secure erasure. A failed job
is skipped during the scan so later jobs can
proceed; an unreadable queue/keyring still requires recovery. Upload/grant
workers report unexpected exceptions as failures and old-session callbacks keep
the job for retry. Incoming delivery rechecks the session, local
key and sender trust after decryption and storage, and live read receipts target
the verified sender device. An already-completed local write cannot be rolled
back if the session changes inside it; page-based historical receipts still lack
sender-device identity. Corrupt queue records are retained and skippable. See
[DELIVERY_LIMITS.md](DELIVERY_LIMITS.md) for remaining race and recovery limits.

### Isolated delivery concurrency smoke test

`max1m_backend/tools/delivery_load_smoke.py` creates its own temporary database
and performs bounded concurrent reliable sends/retries, sync/ACK, quota
saturation/recovery and parallel upload/grant/download. Its optional loopback
transport exercises local HTTP sockets and retries after closing a TCP connection
without reading the response. It never connects to a production server and uses
synthetic ciphertext with the rate limiter disabled. This is a regression and
diagnostic smoke test, not a replacement for internet, multiple-process,
persistence, long-duration and production-like load testing. See
`DELIVERY_LIMITS.md`.

### Upload recovery follow-up

A per-process admission limit bounds simultaneous authenticated raw and multipart
uploads, and a separately bounded hash executor retains its slot across request
cancellation. Excess requests get 503; retry after a post-publication hash failure
preserves and reuses the reservation. Tests cover concurrent slow requests,
unauthenticated requests and cancellation. Reverse-proxy connection/time limits,
multicontainer quotas, disk capacity and real overload tests remain necessary.
Legacy multipart upload retains the blob if a database commit was attempted but
its result is uncertain, and fsyncs file contents first. This trades automatic
cleanup for possible orphan files; clients may retry with a new ID. Reliable
upload checks existing file hashes off the event loop with a bounded read;
streamed writes and fsync may still block the loop. Stale queue worker callbacks
cannot release a newer active worker. These changes do not establish power-loss
or external-filesystem-mutation guarantees; see `DELIVERY_LIMITS.md`.

### Resource and race follow-up

Server WebSocket sends now use a per-socket bounded queue, timeout and serialized
writes; persistent messages remain available through sync if the live event is
dropped, but transient call/group signaling can still be lost. Other JSON request
bodies are capped before parsing, auth validation errors do not echo credentials,
and message ACK rechecks authorization under the SQLite writer lock. Voice
recording prevents overlap with a stuck previous microphone and ignores old
recording signals; WAV playback validates bounded PCM headers and sample length.
Playback now coalesces rapid requests in one thread and rejects stale GUI events;
blocked audio-driver calls can still prevent shutdown. These are targeted
mitigations, not a global resource cap or a security audit. Real audio hardware,
full GUI, multi-OS and multi-process/slow-network load tests remain open. See [DELIVERY_LIMITS.md](DELIVERY_LIMITS.md).

- Linux isolated process-kill/restart smoke now covers pending message recovery,
  retry/ACK and an interrupted reserved raw upload. Reliable `.upload-*` staging
  files now hold an advisory exclusive POSIX `flock` until publication/unlink,
  and startup/maintenance `sweep_orphaned_upload_staging` reclaims only dead
  unlocked single-link `.upload-*` files older than the grace window; abandoned
  DB `UploadReservation` rows still require explicit administrative policy.
  The smoke also injects crashes after
  publication before DB commit and after commit before response; both retry paths
  were checked. This is not a power-loss test. A read-only aggregate audit for
  detached, consistent offline snapshots is available (`upload-recovery-audit.md`);
  it neither determines deletion safety nor performs cleanup.

- Reliable-send confirmations check echoed ciphertext, signature, sender and,
  when present, receiver device as well as UUID before removing a desktop queue
  item. Updated servers echo the receiver; older responses remain compatible but
  cannot verify it. An echo cannot prove persistence/delivery against a malicious
  relay. Reliable upload/grant rejects invalid path IDs before HTTP and uploads
  outside the desktop size limit before sending; records remain for recovery.
- Delivery ACK accepts only a bounded JSON `status: ok` response and bounds the
  outgoing ID list. An invalid or lost response remains uncertain; the next sync
  scan retries pending messages, while already-stored messages remain idempotent.
- Registration now chains directly into authenticated device login instead of
  opening an unauthenticated main screen without a token or WebSocket, and login
  immediately triggers outbox/attachment-outbox processing and refreshes settings
  and archived group cards. POSIX directory `fsync` is performed best-effort
  after atomic local state, history, group-index and outbox renames/unlinks;
  hardware power-loss durability is still not claimed.
- Account device listing (`GET /auth/devices`), atomic peer-device revocation
  (`POST /auth/devices/{id}/revoke` with active-device quotas and immediate
  in-process WebSocket termination), and the desktop Settings device management
  panel are implemented. Reopening a chat restores `⏳` for queued messages and
  attachments, renders/plays pending outgoing attachments from authenticated
  local `attachment_outbox` blobs, and separates `✓` from `✓✓`. The legacy
  `clear.py` helper no longer wipes keyring entries on import and requires
  explicit CLI flags plus the desktop instance lock.
- Contact trust records now persist in authenticated `allies.enc` with owner
  binding and anti-downgrade precedence over legacy `allies.json`; per-profile
  `device_identity.enc`, server-URL pinning on login, and safe session logout
  enable multi-account switching without losing `device_id`. Incoming WebSocket
  signaling frames enforce a per-connection token-bucket rate limit and top-level
  field whitelist, and file download/grant endpoints reject symlinks and dot-files.
- Delivered personal messages older than the configured retention window are
  compacted into lightweight SHA-256 `message_idempotency` tombstones so DB
  ciphertext rows do not accumulate indefinitely while preserving
  `/messages/send-reliable` idempotency, `409` conflict checks, and
  `/messages/sync-safe` `after` cursors until tombstone TTL expiry; `POST /files/{id}/grant`
  and group lifecycle mutations also serialize and roll back cleanly under
  SQLite `BEGIN IMMEDIATE`. On desktop, deleting an incoming message stays
  strictly local, deleting a pending outgoing message/attachment cancels its
  queued `outbox`/`attachment_outbox` item and upload reservation, chat menu
  cancellation covers `attachment_outbox`, and `diagnose_profile.py` provides
  read-only local profile health diagnostics without exposing secrets.
- Server-side JWT session revocation (`Device.session_version` + `POST /auth/logout`
  supporting current-device, all-device, and `only_other_devices` invalidation),
  automatic secondary-session invalidation on `POST /auth/change-password`,
  `Device.last_seen` updates, `ALLOW_LEGACY_WS_QUERY_TOKEN` enforcement, inactive
  account hiding in `GET /auth/find`, per-account stored file quotas
  (`MAX_STORED_FILES_PER_USER`, `MAX_STORED_BYTES_PER_USER`) with post-commit
  expired-file GC (`UPLOADED_FILE_RETENTION_SECONDS`), pinned `cryptography` in
  `max1m_backend/requirements.txt`, full queue/cache cleanup on desktop
  `_clear_chat`, and bounded LRU eviction + Settings UI controls for `VoiceCache`
  are implemented.
- Sender-side WebSocket relay depth/NaN validation (preventing recipient socket
  disconnects on serialization), `TRUSTED_PROXY_IPS` right-to-left
  `X-Forwarded-For` resolution for rate limiting, default-disabled OpenAPI docs
  (`ENABLE_API_DOCS`), HTTP security / `no-store` headers and `Bearer` log
  redaction on backend, plus automatic desktop lockdown on confirmed remote
  session invalidation (`1008` -> HTTP `401/403`), remote cleartext `http://`
  server URL blocking, redirect/size/path-ID hardening across remaining group
  and legacy upload workers, and post-run worker token scrubbing are implemented.
- Cryptographic Ed25519 public-key and SHA-256 fingerprint binding on device
  registration/login (blocking canonical fingerprint squatting by default plus
  `REQUIRE_VERIFIED_DEVICE_KEYS` strict mode), Argon2id settings wiring with
  transparent hash re-upgrade on login and symmetric JWT algorithm whitelisting,
  and `/groups` ID/cursor/limit/rate-limit bounds on backend, plus zero-trust
  own-device public-key pinning & local fingerprint recomputation in Settings,
  universal `APIClient`/`WebSocketWorker` cleartext remote HTTP blocking, POSIX
  `0700`/`0600` local directory/file permissions, fail-closed `load_local_state`
  with crash-safe startup handling, and `call_envelope` JSON depth/NaN limits
  on desktop are implemented.
- Synchronous read/grant-time file TTL enforcement (`UPLOADED_FILE_RETENTION_SECONDS`),
  per-file recipient grant quota (`MAX_GRANTS_PER_FILE`), server POSIX `0700`/`0600`
  storage/blob modes and SQLite `busy_timeout=5000`, configurable `/messages/*`
  HTTP rate limits and cursor/receiver validation, and canonical Base64 + explicit
  transaction rollback in experimental prekeys on backend, plus decrypted peer
  chat payload depth/NaN/size bounds, `SignalCrypto` & `VoicePeerSession` SDP/ICE
  validation and 0-sample `AudioFrame` crash protection (with live audio amplitude
  log removal), and `VoiceCache` / `history_activation` / `CryptoManager`
  symlink/mode/key-length hardening on desktop are implemented.
- Voice call audio-pipeline overhaul (`VoicePeerSession.decode_frame_to_mono_pcm16`
  planar/interleaved stereo downmix eliminating syllable duplication, sample-rate
  normalization to 48 kHz, monotonic 20 ms `AudioCaptureTrack` pacing with stall
  resync, exact 1920-byte `PyAudioIO` framing with `<= 80 ms` jitter ceiling,
  quadratic PLC fade-out, and hot device switching) plus isolated E2EE WebRTC
  DTLS-SRTP screen sharing (`ScreenPeerSession` on a dedicated `_screen_loop`
  and separate `RTCPeerConnection` with live `smooth`/`balanced`/`sharp` preset
  switching and `SignalCrypto` + `call_envelope` signaling) are implemented.
- Protected Group Chats E2EE v2 (`/groups/v2/create`, `/groups/v2/{id}/distribute-key`,
  `/groups/v2/invite`, `/groups/v2/send` + `/groups/sync-safe` / `/groups/ack`)
  with server- and client-verified canonical Ed25519 signatures, epoch tracking
  (`409` stale-epoch rejection and automatic SenderKey rotation on invite/leave),
  per-message symmetric `HMAC-SHA256` ratchet (`MAX_SKIP=256` single-use
  out-of-order cache), and encrypted local `group_keys.enc` persistence are
  implemented while keeping insecure v1 group endpoints disabled (`503`).
- **Package I (Anti-MITM/DPI & Server Anti-Seizure)**: TLS SPKI Pinning
  (`tls_pinning.py`) across HTTPS and WSS prior to credential transmission,
  CSPRNG bucketed traffic padding (`512..65536` B), E2EE-encrypted group names
  (`"[E2EE]"` on server), SQLite `secure_delete=ON` + `temp_store=MEMORY` on
  server and client, `Device.last_seen` hourly coarsening, and zero-fill wiping
  of single-link (`st_nlink == 1`) expired/deleted upload blobs are implemented.
- **Package II (Endpoint Anti-Forensics)**: Optional `Argon2id` RAM-only Local
  Vault (`local_vault.py`, purging OS `keyring` entries), inactivity auto-lock
  + `Ctrl+Shift+L`, plausibly deniable Duress PIN, `Ctrl+Shift+Backspace` Panic
  Wipe (`secure_wipe_file`), and self-destructing TTL messages across 1-on-1
  chats, v2 groups, and attachments are implemented.
- **Package III (Production X3DH + Signal Double Ratchet for 1-on-1 Chats)**:
  Production `/prekeys` router with mandatory Ed25519 `signed_prekey` signature
  verification, OPK quotas, and `3-DH` fallback, plus `double_ratchet.py`
  (`RatchetStore` on `ratchet_v1.sqlite3` with `secure_delete=ON`, two-phase
  crash-safe `seen_incoming` + `mark_delivery_persisted`, `attachment_commitment`
  in `outbox_policy.py`, and automatic background X3DH bundle publication/claim
  in `MainScreen` / `AppWindow`) are implemented.
- **Package IV (VPN-Free Calls in RU & 2–8 Peer Discord-Grade Group Voice Rooms)**:
  `GET /calls/ice-config` ephemeral `coturn` `HMAC-SHA1` credentials (including
  `turns:<host>:443?transport=tcp`) + encrypted client UI `Relay-Only` IP-hiding
  toggle, plus RAM-only `/calls/groups/{id}/voice/*` presence/E2EE signaling and
  `group_voice_room.py` (`VoiceActivityGate` VAD/Noise Gate + Push-to-Talk,
  `BroadcasterMicDistributor` mic fan-out, `GroupAudioMixer` `0–200%` per-peer
  gain + soft-knee `tanh` limiter, live speaking indicators, and 1-click isolated
  peer screen-share viewing) are implemented.



