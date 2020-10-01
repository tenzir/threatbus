from datetime import timedelta
import unittest

from threatbus.data import (
    Subscription,
    Unsubscription,
)
from threatbus_zmq_app.message_mapping import map_management_message


class TestMessageMapping(unittest.TestCase):
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
