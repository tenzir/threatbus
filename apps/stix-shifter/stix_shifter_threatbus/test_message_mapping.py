import unittest
from stix2 import Indicator, Sighting
from .message_mapping import map_bundle_to_sightings


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.observations = [
            {
                "type": "identity",
            },
            {"type": "observed-data", "some-prop": "value"},
            {
                "type": "observed-data",
                "some-prop": "value",
                "last_observed": "2021-05-04T15:15:58.919Z",
            },
        ]
        self.indicator = Indicator(
            pattern="[ipv4-addr:value = '6.6.6.6']", pattern_type="stix"
        )

    def test_map_bundle(self):
        mapped = list(map_bundle_to_sightings(self.indicator, self.observations))
        self.assertEqual(len(mapped), 2)

        for sighting in mapped:
            self.assertEqual(type(sighting), Sighting)
            self.assertEqual(sighting.sighting_of_ref, self.indicator.id)
            self.assertIsNotNone(sighting.last_seen)
