from datetime import datetime
import json
from pymisp import MISPSighting
from stix2 import Indicator, Sighting
from threatbus.data import Operation, Update
from threatbus_misp.message_mapping import (
    attribute_to_stix2_indicator,
    stix2_sighting_to_misp,
    is_whitelisted,
    get_tags,
)
import unittest


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.raw_ts = 1579104545
        self.ts = datetime.fromtimestamp(self.raw_ts)
        self.domain_ioc = "example.com"
        self.ip_ioc = "example.com"
        self.pattern = f"[domain-name:value = '{self.domain_ioc}'] AND [ipv4-addr:value = '{self.ip_ioc}']"
        self.attr_uuid = "5e1f2787-fcfc-4718-a58a-00b4c0a82f06"
        self.indicator_id = f"indicator--{self.attr_uuid}"
        self.indicator = Indicator(
            id=self.indicator_id,
            created=self.ts,
            pattern_type="stix",
            pattern=self.pattern,
        )
        self.sighting = Sighting(created=self.ts, sighting_of_ref=self.indicator_id)
        self.valid_misp_attribute = {
            "id": self.id,
            "event_id": "1",
            "object_id": "0",
            "object_relation": None,
            "category": "Network activity",
            "type": "domain|ip",
            "value1": self.domain_ioc,
            "value2": self.ip_ioc,
            "to_ids": True,
            "uuid": self.attr_uuid,
            "timestamp": str(self.raw_ts),
            "distribution": "5",
            "sharing_group_id": "0",
            "comment": "",
            "deleted": False,
            "disable_correlation": False,
            "value": f"{self.domain_ioc}|{self.ip_ioc}",
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

    def test_invalid_stix_sightings(self):
        self.assertIsNone(stix2_sighting_to_misp(None))
        self.assertIsNone(stix2_sighting_to_misp("Hello"))
        self.assertIsNone(stix2_sighting_to_misp(self))

    def test_invalid_misp_attributes(self):
        self.assertIsNone(attribute_to_stix2_indicator(None, None, None))
        self.assertIsNone(attribute_to_stix2_indicator(None, "delete", None))
        self.assertIsNone(
            attribute_to_stix2_indicator(self.valid_misp_attribute, None, None)
        )

    def test_default_action_remove(self):
        self.assertIsNotNone(
            attribute_to_stix2_indicator(
                self.valid_misp_attribute, "INVALID_ACTION", None
            )
        )

    def test_valid_misp_attributes(self):
        indicator = attribute_to_stix2_indicator(self.valid_misp_attribute, "add", None)
        self.assertEqual(indicator.type, self.indicator.type)
        self.assertEqual(indicator.id, self.indicator.id)
        self.assertEqual(indicator.created, self.indicator.created)
        self.assertEqual(indicator.pattern, self.indicator.pattern)

        single_value_valid_misp_attribute = self.valid_misp_attribute.copy()
        single_value_valid_misp_attribute["type"] = "domain"
        single_value_valid_misp_attribute["value"] = self.domain_ioc
        single_value_valid_misp_attribute["value1"] = self.domain_ioc
        single_value_valid_misp_attribute["value2"] = None
        indicator = attribute_to_stix2_indicator(
            single_value_valid_misp_attribute, "add", None
        )
        self.assertEqual(indicator.type, self.indicator.type)
        self.assertEqual(indicator.id, self.indicator.id)
        self.assertEqual(indicator.created, self.ts)
        self.assertEqual(
            indicator.pattern, f"[domain-name:value = '{self.domain_ioc}']"
        )

    def test_valid_misp_attribute_removal(self):
        valid_misp_attribute = self.valid_misp_attribute.copy()
        valid_misp_attribute["to_ids"] = False
        update = attribute_to_stix2_indicator(valid_misp_attribute, "edit", None)
        self.assertEqual(update, Update(self.indicator_id, Operation.REMOVE))

    def test_valid_stix_sighting(self):
        misp_sighting = stix2_sighting_to_misp(self.sighting)
        self.assertIsNotNone(misp_sighting)
        self.assertEqual(type(misp_sighting), MISPSighting)

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
