from datetime import datetime
import unittest

from threatbus.data import Intel, IntelData, IntelType, Operation, Sighting
from threatbus_misp.message_mapping import map_to_internal, map_to_misp


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.raw_ts = 1579104545
        self.ts = datetime.fromtimestamp(self.raw_ts)
        self.id = "15"
        self.indicator = "example.com"
        self.expected_intel_type = IntelType.DOMAIN
        self.valid_misp_attribute = {
            "id": self.id,
            "event_id": "1",
            "object_id": "0",
            "object_relation": None,
            "category": "Network activity",
            "type": "domain",
            "value1": self.indicator,
            "value2": "",
            "to_ids": True,
            "uuid": "5e1f2787-fcfc-4718-a58a-00b4c0a82f06",
            "timestamp": str(self.raw_ts),
            "distribution": "5",
            "sharing_group_id": "0",
            "comment": "",
            "deleted": False,
            "disable_correlation": False,
            "value": self.indicator,
            "Sighting": [],
        }

    def test_invalid_inputs(self):
        self.assertIsNone(map_to_misp(None))
        self.assertIsNone(map_to_misp("Hello"))
        self.assertIsNone(map_to_misp(self))

    def test_invalid_misp_inputs(self):
        self.assertIsNone(map_to_internal(None, None))
        self.assertIsNone(map_to_internal(None, "delete"))
        self.assertIsNone(map_to_internal(self.valid_misp_attribute, None))

    def test_default_action_remove(self):
        self.assertIsNotNone(map_to_internal(self.valid_misp_attribute, "FOOOO"))

    def test_valid_misp_inputs(self):
        intel_data = IntelData(self.indicator, self.expected_intel_type, source="MISP")
        expected_intel = Intel(self.ts, self.id, intel_data, Operation.ADD)
        self.assertEqual(
            map_to_internal(self.valid_misp_attribute, "add"), expected_intel
        )

    def test_valid_inputs(self):
        sighting = Sighting(self.ts, self.id, {})
        self.assertIsNotNone(map_to_misp(sighting))
