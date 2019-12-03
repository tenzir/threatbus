import unittest
from unittest.mock import ANY, patch, create_autospec

from threatbus import Zeek
from threatbus.zeek import to_zeek
from threatbus.misp import Intelligence


class DummyConfig:
    """Helper to instruct objects under test with a configuration"""

    def __init__(self, host, port, topic):
        self.host = host
        self.port = port
        self.topic = topic


class TestToZeekMapping(unittest.TestCase):
    def test_invalid_mappings(self):

        # malformed types
        self.assertRaises(Exception, to_zeek, None)
        self.assertRaises(Exception, to_zeek, "Foo")
        self.assertRaises(Exception, to_zeek, {"some": "key val dict"})

        # unmappable input
        intel = Intelligence("ID", "type", "value", "data", "source")
        self.assertIsNone(to_zeek(intel))

    def test_valid_mapping(self):
        intel = Intelligence("ID", "ip-src", "127.0.0.1", "data", "source")
        self.assertEqual(to_zeek(intel), ["ID", "ADDR", "127.0.0.1", "source"])


class TestZeek(unittest.TestCase):
    """Tests the functionality of the Zeek class in `threatbus`"""

    @patch("threatbus.zeek.broker.Endpoint")
    @patch.object(Zeek, "put")
    def setUp(self, patched_put, patched_endpoint):
        self.dummy_config = DummyConfig("host1234", 47761, "test/topic")
        self.under_test = Zeek(self.dummy_config)

        patched_endpoint.assert_called_once()
        self.under_test.endpoint.peer.assert_called_with(
            self.dummy_config.host, self.dummy_config.port
        )
        self.under_test.endpoint.make_subscriber.assert_called_with(
            [self.dummy_config.topic]
        )
        patched_put.assert_called_with("Tenzir::hello", ANY)

    @patch("threatbus.zeek.broker.Endpoint")
    @patch("threatbus.zeek.broker.zeek.Event", return_value="ZEEK_EVENT")
    def test_add_intel(self, patched_event, patched_endpoint):
        intel = Intelligence("ID", "ip-src", "127.0.0.1", "data", "source")
        self.under_test.add_intel(intel)
        patched_event.assert_called_with(ANY, ["ID", "ADDR", "127.0.0.1", "source"])
        self.under_test.endpoint.publish.assert_called_with(
            self.dummy_config.topic, patched_event.return_value
        )

    @patch("threatbus.zeek.broker.Endpoint")
    @patch("threatbus.zeek.broker.zeek.Event", return_value="ZEEK_EVENT")
    def test_remove_intel(self, patched_event, patched_endpoint):
        intel = Intelligence("ID", "ip-dst", "6.6.6.6", "data", "dest")
        self.under_test.remove_intel(intel)
        patched_event.assert_called_with(ANY, ["ID", "ADDR", "6.6.6.6", "dest"])
        self.under_test.endpoint.publish.assert_called_with(
            self.dummy_config.topic, patched_event.return_value
        )

    @patch("threatbus.zeek.broker.Endpoint")
    @patch("threatbus.zeek.broker.zeek.Event", return_value="ZEEK_EVENT")
    def test_dump_intel(self, patched_event, patched_endpoint):
        source = "Foo"
        self.under_test.dump_intel(source)
        patched_event.assert_called_with(ANY, source)
        self.under_test.endpoint.publish.assert_called_with(
            self.dummy_config.topic, patched_event.return_value
        )

    @patch("threatbus.zeek.broker.Endpoint")
    @patch("threatbus.zeek.broker.zeek.Event", return_value="ZEEK_EVENT")
    def test_put(self, patched_event, patched_endpoint):
        event_name = "NAME"
        data = "DATA"
        self.under_test.put(event_name, data)
        patched_event.assert_called_with(event_name, data)
        self.under_test.endpoint.publish.assert_called_with(
            self.dummy_config.topic, patched_event.return_value
        )
