"""Synthetic transaction study only. Not used by the application.

This is NOT secure-erasure or rollback protection and must never hold real keys.
"""
import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager

from nacl.secret import SecretBox


class Conflict(ValueError):
    pass


class Store:
    def __init__(self, path, key, scope):
        if len(scope) != 4 or any(not isinstance(x, str) or not x for x in scope):
            raise ValueError("Invalid scope")
        self.scope = hashlib.sha256(json.dumps(scope, separators=(",", ":")).encode()).digest()
        self.box = SecretBox(key)
        self.path = str(path)
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS scope (id INTEGER PRIMARY KEY CHECK(id=1), digest BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, value BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS outgoing (id TEXT PRIMARY KEY, value BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS sent_history (id TEXT PRIMARY KEY, value BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS incoming (id TEXT PRIMARY KEY, value BLOB NOT NULL)")
            previous = db.execute("SELECT digest FROM scope WHERE id=1").fetchone()
            if previous is None:
                db.execute("INSERT INTO scope VALUES (1, ?)", (self.scope,))
            elif previous[0] != self.scope:
                raise Conflict("Wrong account, server or peer")

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _encrypt(self, obj):
        return bytes(self.box.encrypt(json.dumps({"scope": self.scope.hex(), "data": obj}, separators=(",", ":"), sort_keys=True).encode()))

    def _decrypt(self, encrypted):
        value = json.loads(self.box.decrypt(encrypted))
        if value.get("scope") != self.scope.hex(): raise Conflict("Encrypted scope mismatch")
        return value["data"]

    def init(self, state):
        with self._transaction() as db:
            if db.execute("SELECT id FROM state WHERE id=1").fetchone():
                raise Conflict("State already initialized")
            db.execute("INSERT INTO state VALUES(1, 0, ?)", (self._encrypt(state),))

    def snapshot(self):
        with self._transaction() as db:
            row = db.execute("SELECT version, value FROM state WHERE id=1").fetchone()
            if not row: raise Conflict("Missing state")
            return row[0], self._decrypt(row[1])

    def _advance(self, db, expected, state):
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
            raise ValueError("Invalid version")
        changed = db.execute("UPDATE state SET version=version+1, value=? WHERE id=1 AND version=?",
                             (self._encrypt(state), expected)).rowcount
        if changed != 1: raise Conflict("Stale state")

    def commit_outgoing(self, expected, state, identifier, wire, history, fault=None):
        if not isinstance(identifier, str) or not identifier or not isinstance(wire, str) or not wire:
            raise ValueError("Invalid outgoing")
        with self._transaction() as db:
            if db.execute("SELECT id FROM sent_history WHERE id=?", (identifier,)).fetchone():
                raise Conflict("Outgoing ID already exists; read existing bytes instead of re-encrypting")
            self._advance(db, expected, state)
            if fault: fault()
            db.execute("INSERT INTO outgoing VALUES(?,?)", (identifier, self._encrypt({"id": identifier, "wire": wire})))
            db.execute("INSERT INTO sent_history VALUES(?,?)", (identifier, self._encrypt({"id": identifier, "history": history})))

    def get_outgoing(self, identifier):
        with self._transaction() as db:
            row = db.execute("SELECT value FROM outgoing WHERE id=?", (identifier,)).fetchone()
            if not row: return None
            record = self._decrypt(row[0])
            if record["id"] != identifier: raise Conflict("Outgoing ID mismatch")
            return record

    def get_sent_history(self, identifier):
        with self._transaction() as db:
            row = db.execute("SELECT value FROM sent_history WHERE id=?", (identifier,)).fetchone()
            if not row: return None
            record = self._decrypt(row[0])
            if record["id"] != identifier: raise Conflict("Sent ID mismatch")
            return record["history"]

    def acknowledge_outgoing(self, identifier):
        with self._transaction() as db:
            row = db.execute("SELECT value FROM outgoing WHERE id=?", (identifier,)).fetchone()
            if row and self._decrypt(row[0])["id"] != identifier:
                raise Conflict("Outgoing ID mismatch")
            db.execute("DELETE FROM outgoing WHERE id=?", (identifier,))

    def _check_incoming(self, db, identifier, wire):
        row = db.execute("SELECT value FROM incoming WHERE id=?", (identifier,)).fetchone()
        if not row:
            return False
        record = self._decrypt(row[0])
        if (record["id"] != identifier or not hmac.compare_digest(record["digest"], hashlib.sha256(wire).hexdigest())):
            raise Conflict("Delivery ID collision")
        return True

    def seen_incoming(self, identifier, wire):
        # An exact match is already authenticated and durably recorded; allows
        # idempotent ACK even though its ratchet key has been consumed.
        if not isinstance(identifier, str) or not identifier or not isinstance(wire, bytes) or not wire:
            raise ValueError("Invalid incoming")
        with self._transaction() as db:
            return self._check_incoming(db, identifier, wire)

    def commit_incoming(self, expected, state, identifier, wire, history, fault=None):
        """Call only after cryptographic authentication on a staged state."""
        if not isinstance(identifier, str) or not identifier or not isinstance(wire, bytes) or not wire:
            raise ValueError("Invalid incoming")
        with self._transaction() as db:
            if self._check_incoming(db, identifier, wire):
                return False
            self._advance(db, expected, state)
            if fault: fault()
            value = {"id": identifier, "digest": hashlib.sha256(wire).hexdigest(), "history": history}
            db.execute("INSERT INTO incoming VALUES(?,?)", (identifier, self._encrypt(value)))
            return True

    def get_incoming(self, identifier):
        with self._transaction() as db:
            row = db.execute("SELECT value FROM incoming WHERE id=?", (identifier,)).fetchone()
            if not row: return None
            record = self._decrypt(row[0])
            if record["id"] != identifier: raise Conflict("Incoming ID mismatch")
            return record["history"]
