from datetime import timedelta
import unittest

from threatbus.data import (
    Subscription,
    Unsubscription,
)
from threatbus_zmq.message_mapping import Heartbeat, map_management_message


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.topic = "some/topic"

    def test_valid_subscription(self):
        # without snapshot
        msg = {"action": "subscribe", "topic": self.topic}
        td = timedelta(0)
        subscription = map_management_message(msg)
        expected = Subscription(self.topic, td)
        self.assertEqual(subscription, expected)

        # with snapshot:
        msg = {"action": "subscribe", "snapshot": 17, "topic": self.topic}
        td = timedelta(17)
        subscription = map_management_message(msg)
        expected = Subscription(self.topic, td)
        self.assertEqual(subscription, expected)

    def test_valid_unsubscription(self):
        msg = {"action": "unsubscribe", "topic": self.topic}
        unsub = map_management_message(msg)
        expected = Unsubscription(self.topic)
        self.assertEqual(unsub, expected)

    def test_valid_heartbeat(self):
        msg = {"action": "heartbeat", "topic": self.topic}
        hb = map_management_message(msg)
        expected = Heartbeat(self.topic)
        self.assertEqual(hb, expected)
