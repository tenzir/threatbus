import unittest
from unittest.mock import ANY, patch, create_autospec

from threatbus import VAST
from threatbus.misp import Intelligence
from tests.util.dummy_config import VastConfig


expected_expressions = [
    [Intelligence("ID", "ip-src", "127.0.0.1", "data", "source"), ":addr == 127.0.0.1"],
    [
        Intelligence("ID", "ip-dst", "192.168.0.1", "data", "source"),
        ":addr == 192.168.0.1",
    ],
    [
        Intelligence("ID", "domain", "mal.ware.zzz", "data", "source"),
        'host == "mal.ware.zzz"',
    ],
    [
        Intelligence("ID", "url", "example.com/hi", "data", "source"),
        'url == "example.com" && uri == "/hi"',
    ],
    [
        Intelligence("ID", "url", "example.com", "data", "source"),
        'url == "example.com"',
    ],  # note: this fails in the current implementation
]


class TestVast(unittest.TestCase):
    """Tests the functionality of the VAST class in `threatbus`"""

    def setUp(self):
        self.dummy_config = VastConfig("VAST_EXECUTABLE", 10, 10)
        self.under_test = VAST(self.dummy_config)

    def test_make_expression(self):
        for (intel, expected_expr) in expected_expressions:
            expr = self.under_test.make_expression(intel)
            self.assertEqual(expr, expected_expr)
