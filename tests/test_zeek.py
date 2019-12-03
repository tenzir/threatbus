import unittest
from unittest.mock import ANY, patch

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

    def setUp(self):
        self.dummy_config = DummyConfig("host1234", 47761, "test/topic")

        # mock broker
        self.endpoint_patcher = patch("threatbus.zeek.broker.Endpoint")
        self.event_patcher = patch("threatbus.zeek.broker.zeek.Event")
        self.endpoint_patcher.start()
        self.event_patcher.start()
        self.under_test = Zeek(self.dummy_config)

    def tearDown(self):
        self.endpoint_patcher.stop()
        self.event_patcher.stop()

    def test_init(self):
        self.under_test.endpoint.publish.assert_called_with(
            self.dummy_config.topic, ANY
        )
