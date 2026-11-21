# Row-oriented encrypted history: opt-in, experimental

**Кратко:** переход выполняется вручную отдельно для каждого чата и пока
экспериментален. Перед запуском сохраните резервную копию `.max1m` вместе с
ключами keyring и остановите все версии клиента и скрипты. Старый файл истории
остаётся на диске и необходим для проверки; не удаляйте его. Старые версии не
учитывают блокировку и не должны работать с мигрированным профилем. При ошибке
сохраните все файлы и обратитесь к описанию восстановления ниже; автоматического
объединения разошедшихся историй нет.

The desktop can use an encrypted, row-oriented SQLite history **after an explicit
per-chat migration**. It never switches existing histories automatically. The
legacy JSON file remains the default for every unmigrated chat. This feature has
unit, process-crash and callback-level tests, but has **not** been tested with the
full GUI, real devices, all target operating systems or power failures; do not
treat it as production-certified or independently audited.

## Optional migration of one chat

1. Make an independent, restorable backup of the entire `.max1m` directory
   **and its corresponding keyring entries**. Backups can contain sensitive
   encrypted history; without the key they cannot be restored.
2. Stop **all** clients and storage scripts using the directory, including old
   versions. The tool obtains the same Qt lock as the updated desktop, but old
   clients and scripts may ignore it. Do not use old clients against this profile
   after migration: they do not understand the new format.
3. From `max1m_desktop`, in the same environment and OS user/keyring as the
   desktop, run (replace values with the actual local profile and contact):

   ```sh
   python migrate_history.py PROFILE CHAT --confirm-backup-and-stop-old-clients
   ```

   For a group the chat key is `group_<group-id>`. The command requires an
   existing legacy history; it does not migrate every chat or create new empty
   histories. Repeating it on an already active chat is a no-op.
4. Start the updated desktop and check the chat. The old `CHAT.enc` remains an
   immutable migration backup and must remain in place. A changed or missing
   backup blocks access instead of silently falling back to stale data. Do not
   delete the backup, SQLite file, or `history_catalog.enc` to make an error
   disappear: retain all files and use a complete, known-good backup or investigate
   recovery. There is no automatic merge of diverged old and new histories.

The migration reads and decrypts the **whole** legacy file once in memory. It
creates an exclusive temporary DB, verifies every record against the source,
checks a source hash again, publishes the DB without replacing an existing one,
and atomically writes an encrypted per-profile catalog that binds the chat to a
random database ID and source hash. If interrupted after DB publication but
before catalog update, the chat fails closed. Rerunning the command with the
same unchanged source verifies the candidate before completing activation. If a
partial copy or source has changed, it refuses to proceed; it does not remove
anything. Abrupt exit may leave encrypted temporary SQLite/journal files.

## Runtime behavior and limitations

- The current UI uses row storage for migrated chats, including rendering,
  previews, reply navigation, incoming/outgoing saves, read flags and deletes.
  A page retains at most 25 decrypted messages; other rows and the legacy backup
  are streamed. Compatibility methods that explicitly request **all** messages
  still materialize the full result. Legacy chats still load the entire old file.
- The backup is hashed before and after operations; a mismatch is an error. This
  detects many accidental old-client writes but is **not a lock against them**:
  a writer can race a check or restore old bytes. If a mismatch is detected
  after a SQLite transaction committed, its result is uncertain to the caller;
  no successful delivery ACK should be issued, and retry/recovery is required.
  The process lock covers only updated clients using the standard entry point.
- Page/search scans and their backup hashes run in a cancellable worker, but are
  still O(history size). Reply-target lookup and its page also run in the same
  cancellable worker; on SQLite this may require two scans. Previews, writes,
  read-flag updates and their backup hashes can still run on the GUI thread and
  freeze large chats.
  Paging is not a latency or global memory guarantee. Each serialized message is limited to
  8 MiB; 25 large records plus JSON decoding can still consume substantial RAM.
  Read receipts accept up to 1024 IDs in one transaction; larger receipts are
  rejected and remain pending rather than partially applied. This limit also
  applies to unmigrated chats, and no automatic splitting of older receipts is
  provided. A live message received while settings hide the chat stays unread;
  returning to the visible chat can mark the displayed page read.
- Both storage modes reject a repeated message ID with different immutable
  content rather than silently acknowledging it. New legacy deletions preserve
  a keyed content identity inside the encrypted tombstone; identical retries
  do not resurrect the message, and explicit copy migration retains that identity.
  Older tombstones without it cannot be verified and remain pending on retry.
  There is not yet a recovery UI for those tombstones or legacy duplicate IDs.
  Older clients do not enforce these checks and may mutate the backup.
- Explicit clear removes rows in a transaction, but the retained old `.enc`,
  journals, free pages, filesystem snapshots and backups may retain ciphertext.
  Neither clear nor delete provides secure erasure. Users are warned on clear.
- SQLite stores encrypted rows, keyed ID tags, sequence numbers and metadata;
  counts, ordering, ciphertext sizes, file names and access patterns can leak.
  Encryption binds each row to its sequence and tag, and the header to the
  profile/chat and random DB identity. It does **not** detect deletion of rows,
  restoration of an older valid row/database/catalog, or complete rollback of
  all files; no anti-rollback or lost-key recovery is claimed. Reads need a
  writable database because recovery of a hot rollback journal may need writes.
- SQLite uses `synchronous=FULL`, but publication/catalog parent directories are
  not fsynced. Sudden power loss may produce an incomplete cutover or missing
  files. External keyring changes, network filesystems, older clients, and
  concurrency between threads are not comprehensively controlled. Calls through
  `SecureStorage` for one profile are serialized with an in-process reentrant
  lock, including local-key creation and history writes. Direct file access,
  old clients, other processes and external keyring changes bypass that lock.

The GUI keeps one history-page worker and coalesces rapid changes to the newest
request, including reply-target searches. It cancels obsolete scans, checks
account/chat/page/search context and
in-process profile revisions, and checks the revision again under the profile
lock before marking read. Incoming messages during a scan cause a reload. SQLite
reads fetch up to 32 rows or approximately 4 MiB per short read transaction
(one record can exceed that size), then decrypt outside it, so a full scan does
not hold a read transaction or the profile lock across decryption. Legacy reads
use the opened file snapshot, but still decrypt and parse the whole JSON in RAM.
These revisions only cover mutations through `SecureStorage` in this process;
external writers, direct database access and keyring changes bypass them. Continuous
writes may repeatedly invalidate scans. Close requests cancel the worker and are
refused if it cannot stop promptly. Monolithic decrypt/parse and blocking OS,
keyring and SQLite calls cannot be interrupted mid-call. Tests use real QCore
threads and simulated widgets; full GUI behavior has not been verified.

Before broader rollout: a safe recovery/merge workflow, compatibility for large read receipts and legacy
tombstones, production migration/backup UX, multi-OS/power-failure and long-running
network tests, full GUI testing, and independent cryptographic/storage review.
