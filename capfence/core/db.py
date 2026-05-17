"""Database Engine Abstraction layer.

Enables seamless switching between local SQLite databases and production-grade
relational backends (such as PostgreSQL) or mock persistent layers.
"""

from __future__ import annotations

import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, List, Tuple, Dict


class BaseDBEngine(ABC):
    """Abstract Base Class for all CapFence storage engines."""

    @abstractmethod
    def execute(self, query: str, params: Tuple[Any, ...] = ()) -> None:
        """Execute a write/update query within a secure database transaction."""
        pass

    @abstractmethod
    def query(self, query: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
        """Execute a read query and return rows mapped as column-name dictionaries."""
        pass


class SQLiteDBEngine(BaseDBEngine):
    """Production-grade SQLite storage engine supporting WAL journal mode and thread safety."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._persistent_conn: sqlite3.Connection | None = None

        if self.db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(":memory:", check_same_thread=False)

    def _connection(self) -> sqlite3.Connection:
        """Return the active SQLite connection, enabling WAL mode for persistent files."""
        if self._persistent_conn is not None:
            return self._persistent_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def execute(self, query: str, params: Tuple[Any, ...] = ()) -> None:
        conn = self._connection()
        with self._lock:
            conn.execute(query, params)
            conn.commit()

    def query(self, query: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
        conn = self._connection()
        with self._lock:
            cur = conn.execute(query, params)
            rows = cur.fetchall()
            if not cur.description:
                return []
            columns = [d[0] for d in cur.description]
            return [dict(zip(columns, row)) for row in rows]
