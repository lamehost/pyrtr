"""
Key/Value Database persisted through SQLite
"""

import glob
import logging
import os
import re
import sqlite3
from collections.abc import Collection, Iterator, MutableMapping
from typing import Any, Self, override

import msgpack  # pyright: ignore[reportMissingTypeStubs]

logger = logging.getLogger(__name__)


class KVDBView(Collection[Any]):
    """
    Read only view of the Key/Value database

    Arguments:
    ----------
    db_path: os.PathLike[str] | str
        Path to the database
    table str
        SQL table name
    """

    def __init__(self, db_path: os.PathLike[str] | str, table: str):
        self.db_path = db_path
        self.table = table

    @override
    def __contains__(self, item: Any) -> bool:
        with KVDB(self.db_path, self.table) as kvdb:
            return kvdb.__contains__(item)

    @override
    def __iter__(self) -> Iterator[Any]:
        with KVDB(self.db_path, self.table) as kvdb:
            yield from kvdb.values()

    @override
    def __len__(self):
        with KVDB(self.db_path, self.table) as kvdb:
            return len(kvdb)

    @override
    def __repr__(self) -> str:
        return f"<KVDB(path='{self.db_path}', table='{self.table}', status=ReadOnlyView)>"


class KVDB(MutableMapping[bytes, Any]):
    """
    Key/Value database based on SQLite that roughly behaves like a dict.

    Arguments:
    ----------
    db_path: os.PathLike[str] | str
        Path to the database
    table str
        SQL table name
    """

    def __init__(self, db_path: os.PathLike[str] | str, table: str) -> None:
        self.db_path = db_path
        self.table = table
        self._conn = None

    def _execute(self, query: str, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        if self._conn is None:
            raise ValueError("KVDB is closed. Use 'with' or call .open()")

        if re.match(r"[a-z][a-z0-9_\-]+", self.table, re.IGNORECASE) is None:
            raise ValueError(f"Invalid table name: {self.table}")

        logger.debug("Executing query: %s with args: %s and kwargs: %s", query, args, kwargs)
        return self._conn.execute(query.replace("__TABLE__", self.table), *args, **kwargs)

    def open(self) -> Self:
        """
        Open the connection to the database and set journal mode to WAL.
        Creates the database if it doesn't exist

        Returns:
        --------
        Self: The KVDB instance
        """
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, isolation_level=None)
            self._execute("PRAGMA journal_mode=WAL;")
        return self

    def purge(self) -> Iterator[str]:
        """
        Delete the database from the disk

        Yields:
        -------
        Iterator[str]: The name of the files what we have deleted
        """
        for file in glob.glob(f"{self.db_path}*"):
            os.unlink(file)
            yield file

    def create_table(self) -> None:
        """
        Create the table within the database
        """
        self.open()
        self.begin()
        self._execute(
            "CREATE TABLE IF NOT EXISTS `__TABLE__` ("
            "  key BLOB PRIMARY KEY, unserialize BOOL, value BLOB"
            ")"
        )
        self.commit()

    def delete_table(self) -> None:
        """
        Delete the table within the database
        """
        self.open()
        self.begin()
        self._execute("DROP TABLE `__TABLE__`")
        self.commit()

    def commit(self) -> None:
        """
        Commits transaction to the database
        """
        self._execute("COMMIT")

    def rollback(self):
        """
        Rolls back the transation from the database
        """
        self._execute("ROLLBACK")

    def begin(self):
        """
        Begins a transaction
        """
        self._execute("BEGIN")

    def __enter__(self) -> Self:
        """
        Alias for open()
        """
        return self.open()

    def __exit__(self, *_) -> None:
        """
        Alias for close()
        """
        return self.close()

    def __getitem__(self, key: bytes) -> Any:
        """
        Returns value of a key (requires a transtaction).

        Arguments:
        ----------
        key: bytes
            The database key

        Returns:
        --------
        Any: The value corresponding to the key
        """
        cursor = self._execute("SELECT value, unserialize FROM `__TABLE__` WHERE key = ?", (key,))
        row = cursor.fetchone()
        if row is None:
            raise KeyError(key)

        value, unserialize = row
        if unserialize:
            return msgpack.unpackb(value, raw=False)  # type: ignore
        return value

    def __setitem__(self, key: bytes, value: Any) -> None:
        """
        Sets the value for a key (requires a transtaction).

        Arguments:
        ----------
        key: bytes
            The key name
        value: bytes
            The key value
        """
        if isinstance(value, bytes):
            unserialize = False
        else:
            try:
                value = msgpack.packb(value, use_bin_type=True)  # type: ignore
                unserialize = True
            except msgpack.exceptions.PackValueError as error:
                raise ValueError(f"Value cannot be serialized: {error}") from error

        self._execute(
            "INSERT OR REPLACE INTO `__TABLE__` (key, unserialize, value) VALUES (?, ?, ?)",
            (key, unserialize, value),
        )

    def __delitem__(self, key: bytes) -> None:
        """
        Deletes a key from the database (requires a transtaction).

        Arguments:
        ----------
        key: bytes
            The key name
        """
        self._execute("DELETE FROM `__TABLE__` WHERE key = ?", (key,))

    def __iter__(self) -> Iterator[Any]:
        """
        Yields the keys in the database

        Yields:
        -------
        Iterator[bytes]: The keys
        """
        cursor = self._execute("SELECT key FROM `__TABLE__`")
        for row in cursor:
            yield row[0]

    def __len__(self) -> int:
        """
        Returns the amount of keys in the database

        Returns:
        --------
        int: The number of keys
        """

        cursor = self._execute("SELECT COUNT(*) FROM `__TABLE__`")
        return next(iter(cursor.fetchone()))

    def close(self) -> None:
        """
        Disconnects from the database
        """
        if self._conn:
            self._conn.close()
            self._conn = None

    @override
    def __repr__(self) -> str:
        """
        Represents the KVDB object

        Returns:
        --------
        str: The textual representation
        """
        status = "Open" if self._conn else "Closed"
        return f"<KVDB(path='{self.db_path}', table='{self.table}', status={status})>"
