from __future__ import annotations

from contextlib import closing, contextmanager
import json
from pathlib import Path
import sqlite3
from threading import local
from typing import Iterator

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.session import SessionEvent, SessionSnapshot


class SQLiteSessionStore:
    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5_000) -> None:
        if busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be positive")
        self.path = Path(path).expanduser().resolve(strict=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._busy_timeout_ms = busy_timeout_ms
        self._local = local()
        self._initialise()

    def claim_request(
        self,
        request_id: str,
        principal_id: str,
        *,
        now: int,
    ) -> bool:
        if not request_id or not principal_id:
            raise ValueError("request and principal identifiers are required")
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO request_claims
                    (request_id, principal_id, claimed_at)
                VALUES (?, ?, ?)
                """,
                (request_id, principal_id, now),
            )
        return cursor.rowcount == 1

    @contextmanager
    def serialise(self, principal_id: str, session_id: str) -> Iterator[None]:
        if getattr(self._local, "connection", None) is not None:
            raise RuntimeError("nested SQLite session transactions are unsupported")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._local.connection = connection
            self._local.session_key = (principal_id, session_id)
            yield
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            self._local.connection = None
            self._local.session_key = None
            connection.close()

    def snapshot(self, principal_id: str, session_id: str) -> SessionSnapshot:
        connection, owned = self._connection_for(principal_id, session_id)
        try:
            rows = connection.execute(
                """
                SELECT sequence, request_id, tool, effects_json
                FROM session_events
                WHERE principal_id = ? AND session_id = ?
                ORDER BY sequence
                """,
                (principal_id, session_id),
            ).fetchall()
        finally:
            if owned:
                connection.close()
        events = tuple(
            SessionEvent(
                sequence=row[0],
                request_id=row[1],
                tool=row[2],
                effects=frozenset(json.loads(row[3])),
            )
            for row in rows
        )
        return SessionSnapshot(principal_id, session_id, events)

    def record_success(
        self,
        principal_id: str,
        session_id: str,
        request_id: str,
        tool: str,
        effects: frozenset[str],
    ) -> SessionEvent:
        connection, owned = self._connection_for(principal_id, session_id)
        try:
            if owned:
                connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT COALESCE(MAX(sequence), 0) + 1
                FROM session_events
                WHERE principal_id = ? AND session_id = ?
                """,
                (principal_id, session_id),
            ).fetchone()
            sequence = int(row[0])
            connection.execute(
                """
                INSERT INTO session_events
                    (principal_id, session_id, sequence, request_id, tool, effects_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    principal_id,
                    session_id,
                    sequence,
                    request_id,
                    tool,
                    canonical_json(sorted(effects)),
                ),
            )
            if owned:
                connection.commit()
        except BaseException:
            if owned:
                connection.rollback()
            raise
        finally:
            if owned:
                connection.close()
        return SessionEvent(sequence, request_id, tool, frozenset(effects))

    def _connection_for(
        self,
        principal_id: str,
        session_id: str,
    ) -> tuple[sqlite3.Connection, bool]:
        active = getattr(self._local, "connection", None)
        if active is None:
            return self._connect(), True
        if getattr(self._local, "session_key", None) != (principal_id, session_id):
            raise RuntimeError("active SQLite transaction belongs to another session")
        return active, False

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialise(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS request_claims (
                    request_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    claimed_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS session_events (
                    principal_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    tool TEXT NOT NULL,
                    effects_json TEXT NOT NULL,
                    PRIMARY KEY (principal_id, session_id, sequence)
                );
                """
            )
        self.path.chmod(0o600)
