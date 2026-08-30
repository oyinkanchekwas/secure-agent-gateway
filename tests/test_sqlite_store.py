from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
import unittest

from secure_agent_gateway.sqlite_store import SQLiteSessionStore

from tests.support import NOW, make_gateway, make_request, sign


class SQLiteSessionStoreTests(unittest.TestCase):
    def test_failed_transaction_does_not_commit_an_effect(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteSessionStore(Path(directory) / "gateway-state.sqlite3")
            with self.assertRaisesRegex(RuntimeError, "stop transaction"):
                with store.serialise("agent-1", "session-1"):
                    store.record_success(
                        "agent-1",
                        "session-1",
                        "req-1",
                        "read_customer",
                        frozenset({"data.customer"}),
                    )
                    raise RuntimeError("stop transaction")

            snapshot = store.snapshot("agent-1", "session-1")

        self.assertEqual(snapshot.events, ())

    def test_session_history_survives_store_restart(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "gateway-state.sqlite3"
            first = SQLiteSessionStore(path)
            with first.serialise("agent-1", "session-1"):
                first.record_success(
                    "agent-1",
                    "session-1",
                    "req-1",
                    "read_customer",
                    frozenset({"data.customer"}),
                )

            reopened = SQLiteSessionStore(path)
            snapshot = reopened.snapshot("agent-1", "session-1")

        self.assertEqual(len(snapshot.events), 1)
        self.assertEqual(snapshot.events[0].effects, frozenset({"data.customer"}))

    def test_duplicate_request_is_denied_after_gateway_restart(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / "gateway-state.sqlite3"
            first = make_gateway(
                base,
                session_store=SQLiteSessionStore(path),
            )
            request = make_request()
            initial = first.gateway.submit(sign(request), now=NOW)

            second = make_gateway(
                base,
                session_store=SQLiteSessionStore(path),
            )
            replay = second.gateway.submit(sign(request), now=NOW + 1)

        self.assertEqual(initial.status, "succeeded")
        self.assertEqual(replay.status, "denied")
        self.assertEqual(replay.error_code, "request.duplicate_id")
        self.assertEqual(second.calls, [])

    def test_two_store_instances_serialise_effect_commit_before_read(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "gateway-state.sqlite3"
            first = SQLiteSessionStore(path)
            second = SQLiteSessionStore(path)
            first_entered = Event()
            release_first = Event()
            second_entered = Event()
            observations: list[int] = []

            def write_first() -> None:
                with first.serialise("agent-1", "session-1"):
                    first_entered.set()
                    release_first.wait(timeout=2)
                    first.record_success(
                        "agent-1",
                        "session-1",
                        "req-1",
                        "read_customer",
                        frozenset({"data.customer"}),
                    )

            def read_second() -> None:
                first_entered.wait(timeout=1)
                with second.serialise("agent-1", "session-1"):
                    second_entered.set()
                    observations.append(
                        len(second.snapshot("agent-1", "session-1").events)
                    )

            first_thread = Thread(target=write_first)
            second_thread = Thread(target=read_second)
            first_thread.start()
            self.assertTrue(first_entered.wait(timeout=1))
            second_thread.start()
            self.assertFalse(second_entered.wait(timeout=0.1))
            release_first.set()
            first_thread.join(timeout=2)
            second_thread.join(timeout=2)

        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertEqual(observations, [1])


if __name__ == "__main__":
    unittest.main()
