"""Explicit opt-in migration of ONE legacy history. See docs/history-store.md."""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description='Copy and activate one encrypted chat history; legacy copy is retained.')
    parser.add_argument('owner', help='local profile username')
    parser.add_argument('chat', help='contact username or group_<group-id>')
    parser.add_argument('--confirm-backup-and-stop-old-clients', action='store_true',
                        help='confirm an independent backup exists and ALL old clients/scripts are stopped')
    args = parser.parse_args()
    if not args.confirm_backup_and_stop_old_clients:
        parser.error('Back up the profile and stop all clients first, then pass --confirm-backup-and-stop-old-clients')
    from app.history_activation import migrate_chat
    try:
        changed = migrate_chat(args.owner, args.chat)
    except Exception as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(f'Migration failed: {detail}. Original files were not deleted; see docs/history-store.md.', file=sys.stderr)
        return 1
    print('Migration complete; the old encrypted history was retained.' if changed else 'History was already migrated; no changes made.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
