import unittest
import json
from unittest.mock import ANY, patch

from threatbus import MISP
from threatbus.misp import Action
from tests.util.dummy_config import MispConfig, MispRestConfig, MispZmqConfig


ATTRIBUTE = """{
    "id": 1,
    "type": "src-ip",
    "category": "Network activity",
    "to_ids": false,
    "distribution": "0",
    "comment": "",
    "value": "6.6.6.6"
}"""


class TestMisp(unittest.TestCase):
    """Tests the functionality of the VAST class in `threatbus`"""

    @patch("threatbus.misp.zmq.asyncio.Context")
    def setUp(self, patched_context):
        zmq = MispZmqConfig("localhost", 50000)
        rest = MispRestConfig("API_KEY", "https://localhost", False)
        self.dummy_config = MispConfig(rest, zmq, None, None)
        self.under_test = MISP(self.dummy_config)

    def test_intel(self):
        attr = json.loads(ATTRIBUTE)

        # no to_ids field, attr added
        intel = {"Attribute": attr}
        result = self.under_test.process_intel(intel)
        self.assertIsNone(result)

        # no to_ids fields, attr edited
        intel = {"Attribute": attr, "Event": {"id": 1}}
        result = self.under_test.process_intel(intel)
        self.assertEqual(result[0].value, Action.REMOVE.value)
        self.assertEqual(result[1].type, "src-ip")
        self.assertEqual(result[1].value, "6.6.6.6")

        # no to_ids fields, attr deleted
        attr["deleted"] = 1
        intel = {"Attribute": attr, "Event": {"id": 1}}
        result = self.under_test.process_intel(intel)
        self.assertEqual(result[0].value, Action.REMOVE.value)
        self.assertEqual(result[1].type, "src-ip")
        self.assertEqual(result[1].value, "6.6.6.6")
