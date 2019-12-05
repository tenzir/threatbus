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
        Intelligence("ID", "url", "example.com/path", "data", "source"),
        '(host == "example.com" && uri == "/path")',
    ],
    [
        Intelligence("ID", "url", "example.com", "data", "source"),
        'host == "example.com"',
    ],
    [
        Intelligence("ID", "uri", "example.com", "data", "source"),
        'host == "example.com"',
    ],
    [
        Intelligence("ID", "uri", "ftp://example.com", "data", "source"),
        'host == "example.com"',
    ],
    [
        Intelligence("ID", "uri", "https://example.com/", "data", "source"),
        '(host == "example.com" && uri == "/")',
    ],
    [Intelligence("ID", "http-method", "PUT", "data", "source"), 'method == "PUT"',],
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

    def test_make_conjunction(self):
        con = self.under_test.make_conjunction(None)
        self.assertEqual(con, "")

        con = self.under_test.make_conjunction(["A"])
        self.assertEqual(con, "A")

        con = self.under_test.make_conjunction(["A", "B"])
        self.assertEqual(con, "(A && B)")

        con = self.under_test.make_conjunction(["A", "B", "C"])
        self.assertEqual(con, "(A && B && C)")

    def test_make_disjunction(self):
        dis = self.under_test.make_disjunction(None)
        self.assertEqual(dis, "")

        dis = self.under_test.make_disjunction(["A"])
        self.assertEqual(dis, "A")

        dis = self.under_test.make_disjunction(["A", "B"])
        self.assertEqual(dis, "(A || B)")

        dis = self.under_test.make_disjunction(["A", "B", "C"])
        self.assertEqual(dis, "(A || B || C)")
