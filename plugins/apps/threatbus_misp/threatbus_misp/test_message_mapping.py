from datetime import datetime
import json
import unittest

from threatbus.data import Intel, IntelData, IntelType, Operation, Sighting
from threatbus_misp.message_mapping import (
    map_to_internal,
    map_to_misp,
    is_whitelisted,
    get_tags,
)


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
            "Tag": [],
        }
        self.valid_misp_msg = json.loads(
            """{
        "Attribute": {
            "id": "1",
            "event_id": "1",
            "object_id": "0",
            "object_relation": null,
            "category": "Network activity",
            "type": "ip-src",
            "value1": "6.6.6.6",
            "value2": "",
            "to_ids": true,
            "uuid": "5f7b2284-bdd8-4ef4-b457-032ac0a82f02",
            "timestamp": "1601906335",
            "distribution": "5",
            "sharing_group_id": "0",
            "comment": "",
            "deleted": false,
            "disable_correlation": false,
            "first_seen": null,
            "last_seen": null,
            "value": "6.6.6.6",
            "Tag": [
            {
                "id": "3",
                "name": "baz",
                "colour": "#05ff00",
                "exportable": true
            },
            {
                "id": "1",
                "name": "foo",
                "colour": "#ff0000",
                "exportable": true
            }
            ],
            "Sighting": []
        },
        "Event": {
            "id": "1",
            "date": "2020-10-05",
            "info": "evil",
            "uuid": "5f7b2277-1ebc-4101-9152-032ac0a82f02",
            "published": false,
            "analysis": "0",
            "threat_level_id": "1",
            "org_id": "1",
            "orgc_id": "1",
            "distribution": "1",
            "sharing_group_id": "0",
            "Orgc": {
            "id": "1",
            "uuid": "5f7b21ea-52a4-49f0-87df-032ac0a82f02",
            "name": "ORGNAME"
            }
        },
        "action": "edit"
        }
        """
        )

    def test_invalid_threatbus_sightings(self):
        self.assertIsNone(map_to_misp(None))
        self.assertIsNone(map_to_misp("Hello"))
        self.assertIsNone(map_to_misp(self))

    def test_invalid_misp_intel(self):
        self.assertIsNone(map_to_internal(None, None))
        self.assertIsNone(map_to_internal(None, "delete"))
        self.assertIsNone(map_to_internal(self.valid_misp_attribute, None))

    def test_default_action_remove(self):
        self.assertIsNotNone(map_to_internal(self.valid_misp_attribute, "FOOOO"))

    def test_valid_misp_intel(self):
        intel_data = IntelData(self.indicator, self.expected_intel_type, source="MISP")
        expected_intel = Intel(self.ts, self.id, intel_data, Operation.ADD)
        self.assertEqual(
            map_to_internal(self.valid_misp_attribute, "add"), expected_intel
        )

    def test_valid_threatbus_sighting(self):
        sighting = Sighting(self.ts, self.id, {}, (self.indicator,))
        self.assertIsNotNone(map_to_misp(sighting))

    def test_invalid_tags(self):
        attr = self.valid_misp_msg["Attribute"]
        del attr["Tag"]
        tags = get_tags(attr)
        self.assertEqual(tags, [])

        attr["Tag"] = []
        tags = get_tags(attr)
        self.assertEqual(tags, [])

        attr["Tag"] = [{"some": "property"}]
        tags = get_tags(attr)
        self.assertEqual(tags, [])

    def test_valid_tags(self):
        attr = self.valid_misp_msg["Attribute"]
        tags = get_tags(attr)
        self.assertEqual(sorted(tags), sorted(["foo", "baz"]))

    def test_invalid_message_is_whitelisted(self):
        event = self.valid_misp_msg["Event"]
        filter_config = {}  # nothing whitelisted means everything is whitelisted

        del self.valid_misp_msg["Event"]
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        self.valid_misp_msg["Event"] = event
        del self.valid_misp_msg["Attribute"]
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

    def test_valid_message_is_whitelisted(self):

        # positive tests with one filter:
        filter_config = []
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["1", "100"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["foo", "ASDF"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"types": ["domain", "ip-src"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["1"], "tags": ["foo"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["1"], "types": ["ip-src"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["foo"], "types": ["ip-src"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["1"], "tags": ["foo"], "types": ["ip-src"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        # positive tests with multiple filters where only one matches
        filter_config = [{"orgs": ["1"]}, {"orgs": ["5"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["1"]}, {"types": ["ASDF"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["foo"]}, {"types": ["ASDF"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        # positive tests with multiple filters where many match
        filter_config = [{"tags": ["foo"]}, {"types": ["ip-src"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["baz"]}, {"org": ["1"]}]
        self.assertTrue(is_whitelisted(self.valid_misp_msg, filter_config))

        # negative tests with one filter:
        filter_config = [{"orgs": ["100"]}]  # org doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["ASDF"]}]  # tag doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"types": ["domain"]}]  # type doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["1"], "tags": ["ASDF"]}]  # tag doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"types": ["ip-src"], "tags": ["ASDF"]}]  # tag doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["1"], "types": ["domain"]}]  # type doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["foo"], "types": ["domain"]}]  # type doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"types": ["src-ip"], "orgs": ["100"]}]  # org doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["foo"], "orgs": ["100"]}]  # org doesn't match
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        # negative tests with multiple filters where none matches
        filter_config = [{"orgs": ["100"]}, {"orgs": ["5"]}]
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"orgs": ["100"]}, {"types": ["ASDF"]}]
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))

        filter_config = [{"tags": ["ASDF"]}, {"types": ["ASDF"]}]
        self.assertFalse(is_whitelisted(self.valid_misp_msg, filter_config))
