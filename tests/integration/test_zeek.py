import asyncio
import broker
import unittest

from unittest.mock import ANY

from threatbus import Zeek
from threatbus.misp import Intelligence
from tests.util.dummy_config import ZeekConfig

from tests.integration.components.simple_broker import receive, send


class TestZeekIntegration(unittest.TestCase):
    """Tests the functionality of the Zeek class in `threatbus` in an integrative setup."""

    def setUp(self):
        self.dummy_config = ZeekConfig("127.0.0.1", 55555, "test/integration")
        self.under_test = Zeek(self.dummy_config)

        name, data = receive()

        self.assertEqual(name, "Tenzir::hello")

    def test_add_intel(self):
        intel = Intelligence("ID", "ip-src", "4.4.4.4", "data", "source")
        self.under_test.add_intel(intel)

        name, data = receive()

        self.assertEqual(name, "Tenzir::add_intel")
        self.assertEqual(data, [("ID", "ADDR", "4.4.4.4", "source")])

    def test_remove_intel(self):
        intel = Intelligence("ID", "ip-src", "7.7.7.7", "data", "whatever")
        self.under_test.remove_intel(intel)

        name, data = receive()

        self.assertEqual(name, "Tenzir::remove_intel")
        self.assertEqual(data, [("ID", "ADDR", "7.7.7.7", "whatever")])

    def test_dump_intel(self):
        source = "SOURCE"
        self.under_test.dump_intel(source)

        name, data = receive()

        self.assertEqual(name, "Tenzir::intel_snapshot_request")
        self.assertEqual(data, [source])

    def test_get(self):
        name = "TEST_GET"
        content = "CONTENT"

        send(self.dummy_config.topic, name, content)

        data = asyncio.run(self.under_test.get())
        received_event = broker.zeek.Event(data)

        self.assertEqual(received_event.name(), name)
        self.assertEqual(received_event.args(), [content])
