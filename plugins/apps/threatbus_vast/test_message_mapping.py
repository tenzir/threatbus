from datetime import datetime, timedelta, timezone
import unittest
import json

from threatbus.data import (
    Intel,
    IntelData,
    IntelType,
    Operation,
    Subscription,
    Unsubscription,
)
from threatbus_vast.message_mapping import (
    map_intel_to_vast,
    map_management_message,
)


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.ts = datetime.now(timezone.utc).astimezone()
        self.id = 42
        self.module_namespace = "TestNamespace"

    def test_invalid_threatbus_intel(self):
        self.assertIsNone(map_intel_to_vast(None))
        self.assertIsNone(map_intel_to_vast(42))
        self.assertIsNone(map_intel_to_vast(object))

    def test_invalid_threatbus_inteldata(self):
        self.assertIsNone(
            map_intel_to_vast(
                {"ts": self.ts, "id": self.id, "operation": Operation.ADD}
            )
        )
        self.assertIsNone(
            map_intel_to_vast(
                {"ts": self.ts, "id": self.id, "operation": Operation.ADD, "data": {},}
            )
        )
        self.assertIsNone(
            map_intel_to_vast(
                {
                    "ts": self.ts,
                    "id": self.id,
                    "operation": Operation.ADD,
                    "data": {"intel_type": "FOO"},
                }
            )
        )

    def test_valid_intel(self):
        data = IntelData("6.6.6.6", IntelType.IPSRC, foo=23)
        op = Operation.REMOVE
        intel = Intel(self.ts, self.id, data, op)
        expected_vast_msg = {
            "ioc": "6.6.6.6",
            "type": "ip",
            "operation": "REMOVE",
            "reference": "threatbus__" + str(self.id),
        }
        vast_msg = map_intel_to_vast(intel)
        self.assertEqual(json.loads(vast_msg), expected_vast_msg)

    def test_valid_subscription(self):
        topic = "some/topic"

        # without snapshot
        msg = {"action": "subscribe", "topic": topic}
        td = timedelta(0)
        subscription = map_management_message(msg)
        expected = Subscription(topic, td)
        self.assertEqual(subscription, expected)

        # with snapshot:
        msg = {"action": "subscribe", "snapshot": 17, "topic": topic}
        td = timedelta(17)
        subscription = map_management_message(msg)
        expected = Subscription(topic, td)
        self.assertEqual(subscription, expected)

    def test_valid_unsubscription(self):
        topic = "some/topic"
        expected = Unsubscription(topic)

        # with snapshot:
        msg = {"action": "unsubscribe", "topic": topic}
        unsub = map_management_message(msg)
        expected = Unsubscription(topic)
        self.assertEqual(unsub, expected)
