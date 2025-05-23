import os
from collections.abc import Generator
from contextlib import contextmanager
from unittest import mock

import pytest
from google.cloud.bigtable import table
from google.cloud.bigtable.row_data import DEFAULT_RETRY_READ_ROWS
from google.rpc.status_pb2 import Status

from sentry.nodestore.bigtable.backend import BigtableNodeStorage
from sentry.utils.kvstore.bigtable import BigtableKVStorage


class MockedBigtableKVStorage(BigtableKVStorage):
    class Cell:
        def __init__(self, value, timestamp):
            self.value = value
            self.timestamp = timestamp

    class Row:
        def __init__(self, table, row_key):
            self.row_key = row_key.encode("utf8")
            self.table = table

        def delete(self):
            self.table._rows.pop(self.row_key, None)

        def set_cell(self, family, col, value, timestamp):
            assert family == "x"
            self.table._rows.setdefault(self.row_key, {})[col] = [
                MockedBigtableKVStorage.Cell(value, timestamp)
            ]

        def commit(self):
            # commits not implemented, changes are applied immediately
            return Status(code=0)

        @property
        def cells(self):
            return {"x": dict(self.table._rows.get(self.row_key) or ())}

    class Table(table.Table):
        def __init__(self):
            self._rows = {}

        def direct_row(self, key):
            return MockedBigtableKVStorage.Row(self, key)

        def read_row(self, row_key, filter_=None, retry=DEFAULT_RETRY_READ_ROWS):
            return MockedBigtableKVStorage.Row(self, row_key)

        def read_rows(
            self,
            start_key=None,
            end_key=None,
            limit=None,
            filter_=None,
            end_inclusive=False,
            row_set=None,
            retry=None,
        ):
            assert not row_set.row_ranges, "unsupported"
            return [self.read_row(key) for key in row_set.row_keys]

        def mutate_rows(self, rows, retry=None, timeout=None):
            # commits not implemented, changes are applied immediately
            return [Status(code=0) for row in rows]

    def _get_table(self, admin: bool = False):
        try:
            table = self.__table
        except AttributeError:
            table = self.__table = MockedBigtableKVStorage.Table()

        return table

    def bootstrap(self, automatic_expiry: bool = True) -> None:
        pass


class MockedBigtableNodeStorage(BigtableNodeStorage):
    store_class = MockedBigtableKVStorage


@contextmanager
def get_temporary_bigtable_nodestorage() -> Generator[BigtableNodeStorage]:
    if "BIGTABLE_EMULATOR_HOST" not in os.environ:
        pytest.skip(
            "Bigtable is not available, set BIGTABLE_EMULATOR_HOST environment variable to enable"
        )

    ns = BigtableNodeStorage(project="test")
    ns.bootstrap()

    try:
        yield ns
    finally:
        ns.store.destroy()


@pytest.fixture(params=[MockedBigtableNodeStorage, BigtableNodeStorage])
def ns(request):
    if request.param is BigtableNodeStorage:
        with get_temporary_bigtable_nodestorage() as ns:
            yield ns
    else:
        yield MockedBigtableNodeStorage(project="test")


@pytest.mark.django_db
def test_cache(ns):
    node_1 = ("a" * 32, {"foo": "a"})
    node_2 = ("b" * 32, {"foo": "b"})
    node_3 = ("c" * 32, {"foo": "c"})

    for node_id, data in [node_1, node_2, node_3]:
        ns.set(node_id, data)

    # Get / get multi populates cache
    assert ns.get(node_1[0]) == node_1[1]
    assert ns.get_multi([node_2[0], node_3[0]]) == {
        node_2[0]: node_2[1],
        node_3[0]: node_3[1],
    }

    table = ns.store._get_table()

    with mock.patch.object(table, "read_row") as mock_read_row:
        assert ns.get(node_1[0]) == node_1[1]
        assert ns.get(node_2[0]) == node_2[1]
        assert ns.get(node_3[0]) == node_3[1]
        assert mock_read_row.call_count == 0

    with mock.patch.object(table, "read_rows") as mock_read_rows:
        assert ns.get_multi([node_1[0], node_2[0], node_3[0]])
        assert mock_read_rows.call_count == 0

    # Manually deleted item should still retrievable from cache
    row = table.direct_row(node_1[0])
    row.delete()
    row.commit()
    assert ns.get(node_1[0]) == node_1[1]
    assert ns.get_multi([node_1[0], node_2[0]]) == {
        node_1[0]: node_1[1],
        node_2[0]: node_2[1],
    }

    # Deletion clears cache
    ns.delete(node_1[0])
    assert ns.get_multi([node_1[0], node_2[0]]) == {node_1[0]: None, node_2[0]: node_2[1]}
    ns.delete_multi([node_1[0], node_2[0]])
    assert ns.get_multi([node_1[0], node_2[0]]) == {node_1[0]: None, node_2[0]: None}

    # Setting the item updates cache
    new_value = {"event_id": "d" * 32}
    ns.set(node_1[0], new_value)
    with mock.patch.object(table, "read_row") as mock_read_row:
        assert ns.get(node_1[0]) == new_value
        assert mock_read_row.call_count == 0

    # Missing rows are never cached
    assert ns.get("node_4") is None
    with mock.patch.object(table, "read_row") as mock_read_row:
        mock_read_row.return_value = None
        ns.get("node_4")
        ns.get("node_4")
        assert mock_read_row.call_count == 2


def test_compression() -> None:
    ns = BigtableNodeStorage(compression="zstd")
    assert ns.store.compression == "zstd"
    ns = BigtableNodeStorage(compression=True)
    assert ns.store.compression == "zlib"
    ns = BigtableNodeStorage(compression=False)
    assert ns.store.compression is None
