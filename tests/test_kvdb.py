"""
Unittests for KVDB and KVDBView classes
"""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from pyrtr.datasources.rpki_client.kvdb import KVDB, KVDBView


class TestKVDB(unittest.TestCase):
    """Test suite for KVDB class"""

    def setUp(self):
        """Create a temporary database for each test"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.table = "test_table"

    def tearDown(self):
        """Clean up temporary database"""
        self.temp_dir.cleanup()

    def test_init(self):
        """Test KVDB initialization"""
        kvdb = KVDB(self.db_path, self.table)
        self.assertEqual(kvdb.db_path, self.db_path)
        self.assertEqual(kvdb.table, self.table)
        self.assertIsNone(kvdb._conn)  # pyright: ignore[reportPrivateUsage]

    def test_open_creates_connection(self):
        """Test that open() creates a database connection"""
        kvdb = KVDB(self.db_path, self.table)
        result = kvdb.open()
        self.assertIsNotNone(kvdb._conn)  # pyright: ignore[reportPrivateUsage]
        self.assertIsInstance(result, KVDB)
        self.assertIs(result, kvdb)
        kvdb.close()

    def test_open_idempotent(self):
        """Test that calling open() multiple times uses same connection"""
        kvdb = KVDB(self.db_path, self.table)
        kvdb.open()
        first_conn = kvdb._conn  # pyright: ignore[reportPrivateUsage]
        kvdb.open()
        self.assertIs(kvdb._conn, first_conn)  # pyright: ignore[reportPrivateUsage]
        kvdb.close()

    def test_close(self):
        """Test that close() disconnects from database"""
        kvdb = KVDB(self.db_path, self.table)
        kvdb.open()
        self.assertIsNotNone(kvdb._conn)  # pyright: ignore[reportPrivateUsage]
        kvdb.close()
        self.assertIsNone(kvdb._conn)  # pyright: ignore[reportPrivateUsage]

    def test_context_manager(self):
        """Test KVDB as context manager"""
        kvdb = KVDB(self.db_path, self.table)
        with kvdb as db:
            self.assertIsNotNone(db._conn)  # pyright: ignore[reportPrivateUsage]
            self.assertIs(db, kvdb)
        self.assertIsNone(kvdb._conn)  # pyright: ignore[reportPrivateUsage]

    def test_execute_without_connection_raises_error(self):
        """Test that _execute raises ValueError when not connected"""
        kvdb = KVDB(self.db_path, self.table)
        with self.assertRaises(ValueError) as context:
            kvdb._execute("SELECT 1")  # pyright: ignore[reportPrivateUsage]
        self.assertIn("KVDB is closed", str(context.exception))

    def test_invalid_table_name(self):
        """Test that invalid table names are rejected"""
        with self.assertRaises(ValueError) as context:
            kvdb = KVDB(self.db_path, "123invalid")
            kvdb.open()
        self.assertIn("Invalid table name", str(context.exception))

    def test_create_table(self):
        """Test table creation"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            # Verify table exists by checking schema
            cursor = kvdb._execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (self.table,),
            )
            self.assertIsNotNone(cursor.fetchone())

    def test_create_table_idempotent(self):
        """Test that creating table multiple times doesn't raise error"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.create_table()  # Should not raise

    def test_delete_table(self):
        """Test table deletion"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.delete_table()
            # Verify table is deleted
            cursor = kvdb._execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (self.table,),
            )
            self.assertIsNone(cursor.fetchone())

    def test_setitem_getitem_bytes(self):
        """Test setting and getting bytes values"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"test_key"
            value = b"test_value"
            kvdb[key] = value
            kvdb.commit()

            kvdb.begin()
            self.assertEqual(kvdb[key], value)
            kvdb.commit()

    def test_setitem_getitem_dict(self):
        """Test setting and getting non-bytes (dict) values"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"test_key"
            value: dict[str, Any] = {"nested": "dict", "count": 42}
            kvdb[key] = value
            kvdb.commit()

            kvdb.begin()
            retrieved = kvdb[key]
            self.assertEqual(retrieved, value)
            kvdb.commit()

    def test_setitem_getitem_list(self):
        """Test setting and getting list values"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"test_list"
            value: list[Any] = [1, 2, 3, "four", {"five": 5}]
            kvdb[key] = value
            kvdb.commit()

            kvdb.begin()
            retrieved = kvdb[key]
            self.assertEqual(retrieved, value)
            kvdb.commit()

    def test_setitem_overwrite(self):
        """Test that setting same key overwrites value"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"test_key"
            kvdb[key] = b"first_value"
            kvdb.commit()

            kvdb.begin()
            kvdb[key] = b"second_value"
            kvdb.commit()

            kvdb.begin()
            self.assertEqual(kvdb[key], b"second_value")
            kvdb.commit()

    def test_getitem_missing_key_raises_keyerror(self):
        """Test that accessing missing key raises KeyError"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            with self.assertRaises(KeyError):
                _ = kvdb[b"nonexistent_key"]
            kvdb.commit()

    def test_delitem(self):
        """Test deleting a key"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"test_key"
            kvdb[key] = b"value"
            kvdb.commit()

            kvdb.begin()
            del kvdb[key]
            kvdb.commit()

            kvdb.begin()
            with self.assertRaises(KeyError):
                _ = kvdb[key]
            kvdb.commit()

    def test_contains(self):
        """Test __contains__ method"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"test_key"
            kvdb[key] = b"value"
            kvdb.commit()

            kvdb.begin()
            self.assertIn(key, kvdb)
            self.assertNotIn(b"nonexistent", kvdb)
            kvdb.commit()

    def test_iter_keys(self):
        """Test iterating over keys"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            keys = [b"key1", b"key2", b"key3"]
            for key in keys:
                kvdb[key] = b"value"
            kvdb.commit()

            kvdb.begin()
            retrieved_keys = kvdb.keys()
            kvdb.commit()
            self.assertEqual(set(retrieved_keys), set(keys))

    def test_len(self):
        """Test __len__ method"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            self.assertEqual(len(kvdb), 0)

            for i in range(5):
                kvdb[f"key{i}".encode()] = b"value"

            self.assertEqual(len(kvdb), 5)
            kvdb.commit()

    def test_values_iteration(self):
        """Test iterating over values"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            values = [b"value1", b"value2", b"value3"]
            for i, value in enumerate(values):
                kvdb[f"key{i}".encode()] = value
            kvdb.commit()

            kvdb.begin()
            retrieved_values = kvdb.values()
            kvdb.commit()
            self.assertEqual(set(retrieved_values), set(values))

    def test_setitem_invalid_value_raises_error(self):
        """Test that non-serializable values raise ValueError"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()

            # Create an object that msgpack cannot serialize
            class NonSerializable:
                pass

            with self.assertRaises(TypeError) as context:
                kvdb[b"test"] = NonSerializable()
            self.assertIn("can not serialize", str(context.exception))

    def test_begin_commit(self):
        """Test transaction management"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b"key"] = b"value"
            kvdb.commit()

            kvdb.begin()
            self.assertEqual(kvdb[b"key"], b"value")
            kvdb.commit()

    def test_rollback(self):
        """Test transaction rollback"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b"key"] = b"value1"
            kvdb.commit()

            kvdb.begin()
            kvdb[b"key"] = b"value2"
            kvdb.rollback()

            kvdb.begin()
            self.assertEqual(kvdb[b"key"], b"value1")
            kvdb.commit()

    def test_purge(self):
        """Test database purge"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b"key"] = b"value"
            kvdb.commit()

            deleted_files = list(kvdb.purge())
            self.assertGreater(len(deleted_files), 0)
            # Verify files are actually deleted
            for file in deleted_files:
                self.assertFalse(os.path.exists(file))

    def test_repr_open(self):
        """Test __repr__ for open KVDB"""
        with KVDB(self.db_path, self.table) as kvdb:
            repr_str = repr(kvdb)
            self.assertIn("Open", repr_str)
            self.assertIn(str(self.db_path), repr_str)
            self.assertIn(self.table, repr_str)

    def test_repr_closed(self):
        """Test __repr__ for closed KVDB"""
        kvdb = KVDB(self.db_path, self.table)
        repr_str = repr(kvdb)
        self.assertIn("Closed", repr_str)
        self.assertIn(str(self.db_path), repr_str)

    def test_multiple_tables(self):
        """Test using multiple tables in same database"""
        table1 = "table1"
        table2 = "table2"

        with KVDB(self.db_path, table1) as kvdb1:
            kvdb1.create_table()
            kvdb1.begin()
            kvdb1[b"key1"] = b"value1"
            kvdb1.commit()

        with KVDB(self.db_path, table2) as kvdb2:
            kvdb2.create_table()
            kvdb2.begin()
            kvdb2[b"key2"] = b"value2"
            kvdb2.commit()

        # Verify data isolation
        with KVDB(self.db_path, table1) as kvdb1:
            kvdb1.begin()
            self.assertEqual(kvdb1[b"key1"], b"value1")
            with self.assertRaises(KeyError):
                _ = kvdb1[b"key2"]
            kvdb1.commit()


class TestKVDBView(unittest.TestCase):
    """Test suite for KVDBView class"""

    def setUp(self):
        """Create a temporary database for each test"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.table = "test_table"
        # Create and populate database
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b"key1"] = b"value1"
            kvdb[b"key2"] = {"nested": "data"}
            kvdb[b"key3"] = [1, 2, 3]
            kvdb.commit()

    def tearDown(self):
        """Clean up temporary database"""
        self.temp_dir.cleanup()

    def test_init(self):
        """Test KVDBView initialization"""
        view = KVDBView(self.db_path, self.table)
        self.assertEqual(view.db_path, self.db_path)
        self.assertEqual(view.table, self.table)

    def test_contains(self):
        """Test __contains__ method"""
        view = KVDBView(self.db_path, self.table)
        self.assertIn(b"key1", view)
        self.assertNotIn(b"nonexistent", view)

    def test_iter(self):
        """Test iterating over view (yields values)"""
        view = KVDBView(self.db_path, self.table)
        values = list(view)
        self.assertEqual(len(values), 3)
        self.assertIn(b"value1", values)
        self.assertIn({"nested": "data"}, values)
        self.assertIn([1, 2, 3], values)

    def test_len(self):
        """Test __len__ method"""
        view = KVDBView(self.db_path, self.table)
        self.assertEqual(len(view), 3)

    def test_repr(self):
        """Test __repr__ method"""
        view = KVDBView(self.db_path, self.table)
        repr_str = repr(view)
        self.assertIn("ReadOnlyView", repr_str)
        self.assertIn(str(self.db_path), repr_str)
        self.assertIn(self.table, repr_str)

    def test_view_reflects_underlying_changes(self):
        """Test that view reflects changes to underlying database"""
        view = KVDBView(self.db_path, self.table)
        initial_len = len(view)

        # Add new item to database
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.begin()
            kvdb[b"key4"] = b"value4"
            kvdb.commit()

        # View should reflect the change
        self.assertEqual(len(view), initial_len + 1)
        self.assertIn(b"key4", view)


class TestKVDBEdgeCases(unittest.TestCase):
    """Test suite for edge cases and complex scenarios"""

    def setUp(self):
        """Create a temporary database for each test"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.table = "test_table"

    def tearDown(self):
        """Clean up temporary database"""
        self.temp_dir.cleanup()

    def test_large_value(self):
        """Test storing large values"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"large_key"
            value = b"x" * 1000000  # 1MB value
            kvdb[key] = value
            kvdb.commit()

            kvdb.begin()
            self.assertEqual(kvdb[key], value)
            kvdb.commit()

    def test_special_bytes_as_key(self):
        """Test using special bytes as keys"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            keys = [b"\x00\x01\x02", b"\xff\xfe\xfd", b"\n\r\t"]
            for key in keys:
                kvdb[key] = b"value"
            kvdb.commit()

            kvdb.begin()
            for key in keys:
                self.assertEqual(kvdb[key], b"value")
            kvdb.commit()

    def test_unicode_in_serialized_value(self):
        """Test storing unicode strings (serialized)"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"unicode_key"
            value = {"message": "Hello, 世界! 🌍"}
            kvdb[key] = value
            kvdb.commit()

            kvdb.begin()
            retrieved = kvdb[key]
            self.assertEqual(retrieved, value)
            kvdb.commit()

    def test_complex_nested_structure(self):
        """Test deeply nested data structures"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            key = b"complex"
            value = {  # pyright: ignore[reportUnknownVariableType]
                "level1": {"level2": {"level3": [1, 2, {"level4": [True, False, None]}]}}
            }
            kvdb[key] = value
            kvdb.commit()

            kvdb.begin()
            retrieved = kvdb[key]
            self.assertEqual(retrieved, value)
            kvdb.commit()

    def test_pathlike_db_path(self):
        """Test using pathlib.Path as db_path"""
        with KVDB(Path(self.db_path), self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b"key"] = b"value"
            kvdb.commit()
            self.assertIsNotNone(kvdb._conn)  # pyright: ignore[reportPrivateUsage]

    def test_string_db_path(self):
        """Test using string as db_path"""
        with KVDB(str(self.db_path), self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b"key"] = b"value"
            kvdb.commit()
            self.assertIsNotNone(kvdb._conn)  # pyright: ignore[reportPrivateUsage]

    def test_empty_bytes_key(self):
        """Test using empty bytes as key"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b""] = b"empty_key_value"
            kvdb.commit()

            kvdb.begin()
            self.assertEqual(kvdb[b""], b"empty_key_value")
            kvdb.commit()

    def test_none_value(self):
        """Test storing None value (must be serialized)"""
        with KVDB(self.db_path, self.table) as kvdb:
            kvdb.create_table()
            kvdb.begin()
            kvdb[b"none_key"] = None
            kvdb.commit()

            kvdb.begin()
            retrieved = kvdb[b"none_key"]
            self.assertIsNone(retrieved)
            kvdb.commit()

    def test_table_name_with_valid_characters(self):
        """Test table names with various valid characters"""
        valid_names = ["table_name", "table-name", "Table_Name", "TABLE123"]
        for table_name in valid_names:
            db_path = Path(self.temp_dir.name) / f"{table_name}.db"
            with KVDB(db_path, table_name) as kvdb:
                kvdb.create_table()
                kvdb.begin()
                kvdb[b"key"] = b"value"
                kvdb.commit()


if __name__ == "__main__":
    unittest.main()
