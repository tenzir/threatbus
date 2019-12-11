import asyncio
import json
import unittest
import requests
import time
from unittest.mock import ANY, patch

from threatbus import MISP
from threatbus.misp import Intelligence, Action
from tests.util.dummy_config import (
    MispConfig,
    MispRestConfig,
    MispZmqConfig,
    MispSnapshotConfig,
)
from tests.util.async_util import run_await

# TODO automate better
API_KEY = "H7hfrWfpUOGaPqfibb0AMNRHJI8V60aFvEBaEC6w"

ATTRIBUTE = """{
    "id": 1,
    "type": "domain",
    "category": "Network activity",
    "to_ids": false,
    "distribution": "0",
    "comment": "",
    "value": "evil.com"
}"""

EVENT = (
    """{
  "Event": {
    "date": "2019-01-01",
    "threat_level_id": "3",
    "info": "TEST_EVENT",
    "published": false,
    "analysis": "0",
    "distribution": "0",
    "Attribute": ["""
    + ATTRIBUTE
    + """]
  }
}"""
)

MISP_URL = "https://localhost"


class TestMisp(unittest.TestCase):
    """Tests the functionality of the VAST class in `threatbus`"""

    @classmethod
    def setUpClass(cls):
        # fill MISP with test data
        # executed only once
        response = requests.post(
            data=EVENT,
            url=MISP_URL + "/events",
            headers={
                "Accept": "application/json",
                "content-type": "application/json",
                "Authorization": API_KEY,
            },
            verify=False,
        )
        # make created event id available in all test cases
        assert response, "Is MISP running & the API key set?"
        cls.created_event_id = json.loads(response.content)["Event"]["id"]
        assert response.status_code == 200

    # @patch("threatbus.misp.zmq.asyncio.Context")
    def setUp(self):

        # Zmq is mocked / patched. MISP Api has to be real for integration tests
        zmq = MispZmqConfig("localhost", 50000)
        rest = MispRestConfig(API_KEY, MISP_URL, False)
        snapshot = MispSnapshotConfig(False, dict())
        self.dummy_config = MispConfig(rest, zmq, None, snapshot)
        self.under_test = MISP(self.dummy_config)

    def test_report(self):

        # report sighting of the mock event
        sighting_id = int(TestMisp.created_event_id)
        time_seen = time.time()
        run_await(self.under_test.report(sighting_id, time_seen))

        verify_api_response = requests.get(
            url=MISP_URL + "/events/" + TestMisp.created_event_id,
            headers={
                "Accept": "application/json",
                "content-type": "application/json",
                "Authorization": API_KEY,
            },
            verify=False,
        )
        event = json.loads(verify_api_response.content)

        self.assertEqual(event["Event"]["id"], TestMisp.created_event_id)
        sighting = event["Event"]["Attribute"][0]["Sighting"][0]
        self.assertIsNotNone(sighting)
        self.assertEqual(sighting["source"], "VAST")

        # there is a mismatch of misp sighting timestamp and the one we set
        misp_seen = sighting["date_sighting"]
        self.assertLess(abs(float(misp_seen) - time_seen), 2)

    def test_snapshot(self):
        data = run_await(self.under_test.snapshot())
        self.assertIsNotNone(data)
        self.assertGreater(len(data), 0)
        self.assertIs(type(data), list)

        test_event = data[0]
        ground_truth = json.loads(ATTRIBUTE)
        self.assertEqual(test_event.type, ground_truth["type"])
