import broker
from datetime import datetime, timedelta, timezone
import json
from logging import getLogger
from stix2 import Indicator, Sighting, parse
from threatbus.data import (
    Operation,
    Subscription,
    Unsubscription,
    ThreatBusSTIX2Constants,
)
from threatbus_zeek.message_mapping import (
    map_broker_event_to_sighting,
    map_indicator_to_broker_event,
    map_management_message,
)
import unittest


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.ts = datetime.now(timezone.utc).astimezone()
        self.indicator_id = "indicator--de0c3d3f-02ee-4086-88f1-51200ac831f7"
        self.point_ioc = "evil.com"
        self.pattern = f"[domain-name:value = '{self.point_ioc}']"
        self.indicator = Indicator(
            id=self.indicator_id,
            created=self.ts,
            modified=self.ts,
            pattern_type="stix",
            pattern=self.pattern,
        )
        self.module_namespace = "TestNamespace"
        self.logger = getLogger("test")

    def test_invalid_indicator_inputs(self):
        self.assertIsNone(map_indicator_to_broker_event(None, None, self.logger))
        self.assertIsNone(map_indicator_to_broker_event(None, "", self.logger))
        self.assertIsNone(
            map_indicator_to_broker_event(None, self.module_namespace, self.logger)
        )
        self.assertIsNone(
            map_indicator_to_broker_event(42, self.module_namespace, self.logger)
        )
        self.assertIsNone(
            map_indicator_to_broker_event(object, self.module_namespace, self.logger)
        )
        self.assertIsNone(
            map_indicator_to_broker_event(
                Sighting(sighting_of_ref=self.indicator_id),
                self.module_namespace,
                self.logger,
            )
        )

    def test_invalid_zeek_inputs(self):
        broker_data = broker.zeek.Event("Hello")  # unknown event
        self.assertIsNone(map_broker_event_to_sighting(broker_data, None, self.logger))
        self.assertIsNone(
            map_broker_event_to_sighting(
                broker_data, self.module_namespace, self.logger
            )
        )
        self.assertIsNone(map_management_message(broker_data, None, self.logger))
        self.assertIsNone(
            map_management_message(broker_data, self.module_namespace, self.logger)
        )

        # not enough arguments provided
        broker_data = broker.zeek.Event("sighting", 1, 2)
        self.assertIsNone(map_broker_event_to_sighting(broker_data, None, self.logger))
        self.assertIsNone(
            map_broker_event_to_sighting(
                broker_data, self.module_namespace, self.logger
            )
        )
        self.assertIsNone(map_management_message(broker_data, None, self.logger))
        self.assertIsNone(
            map_management_message(broker_data, self.module_namespace, self.logger)
        )

        broker_data = broker.zeek.Event("intel", 42, {})
        self.assertIsNone(map_broker_event_to_sighting(broker_data, None, self.logger))
        self.assertIsNone(
            map_broker_event_to_sighting(
                broker_data, self.module_namespace, self.logger
            )
        )
        self.assertIsNone(map_management_message(broker_data, None, self.logger))
        self.assertIsNone(
            map_management_message(broker_data, self.module_namespace, self.logger)
        )

        broker_data = broker.zeek.Event("subscribe", "topic")
        self.assertIsNone(map_broker_event_to_sighting(broker_data, None, self.logger))
        self.assertIsNone(
            map_broker_event_to_sighting(
                broker_data, self.module_namespace, self.logger
            )
        )
        self.assertIsNone(map_management_message(broker_data, None, self.logger))
        self.assertIsNone(
            map_management_message(broker_data, self.module_namespace, self.logger)
        )

        broker_data = broker.zeek.Event("unsubscribe")
        self.assertIsNone(map_broker_event_to_sighting(broker_data, None, self.logger))
        self.assertIsNone(
            map_broker_event_to_sighting(
                broker_data, self.module_namespace, self.logger
            )
        )
        self.assertIsNone(map_management_message(broker_data, None, self.logger))
        self.assertIsNone(
            map_management_message(broker_data, self.module_namespace, self.logger)
        )

    def test_valid_indicator(self):
        # test indicator added
        broker_msg = map_indicator_to_broker_event(
            self.indicator, self.module_namespace, None
        )
        self.assertEqual(broker_msg.name(), self.module_namespace + "::intel")
        self.assertEqual(
            broker_msg.args(),
            [(self.ts, self.indicator_id, "DOMAIN", self.point_ioc, "ADD")],
        )

        # test indicator removed
        # deep copy indicator, add custom property that indicates deletion
        i_dct = json.loads(self.indicator.serialize())  # deep copy
        i_dct[ThreatBusSTIX2Constants.X_THREATBUS_UPDATE.value] = Operation.REMOVE.value
        indicator_copy = parse(json.dumps(i_dct), allow_custom=True)

        broker_msg = map_indicator_to_broker_event(
            indicator_copy, self.module_namespace, None
        )
        self.assertEqual(broker_msg.name(), self.module_namespace + "::intel")
        self.assertEqual(
            broker_msg.args(),
            [(self.ts, self.indicator_id, "DOMAIN", self.point_ioc, "REMOVE")],
        )

    def test_valid_zeek_sighting(self):
        context = {"last_seen": 1234, "count": 13, "source": "Zeek"}
        # without namespace:
        event = broker.zeek.Event("sighting", self.ts, self.indicator_id, context)
        sighting = map_broker_event_to_sighting(event, self.module_namespace, None)
        self.assertEqual(type(sighting), Sighting)
        self.assertEqual(sighting.last_seen, self.ts)
        self.assertEqual(sighting.sighting_of_ref, self.indicator_id)
        self.assertTrue(
            ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value in sighting
        )
        self.assertEqual(sighting.x_threatbus_sighting_context, context)

        # with namespace:
        event = broker.zeek.Event(
            self.module_namespace + "::sighting", self.ts, self.indicator_id, context
        )
        sighting = map_broker_event_to_sighting(event, self.module_namespace, None)
        self.assertEqual(type(sighting), Sighting)
        self.assertEqual(sighting.last_seen, self.ts)
        self.assertEqual(sighting.sighting_of_ref, self.indicator_id)
        self.assertTrue(
            ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value in sighting
        )
        self.assertEqual(sighting.x_threatbus_sighting_context, context)

    def test_valid_subscription(self):
        td = timedelta(days=5)
        topic = "some/topic"
        expected = Subscription(topic, td)

        # without namespace
        event = broker.zeek.Event("subscribe", topic, td)
        subscription = map_management_message(event, self.module_namespace, self.logger)
        self.assertEqual(subscription, expected)

        # with namespace:
        event = broker.zeek.Event(self.module_namespace + "::subscribe", topic, td)
        subscription = map_management_message(event, self.module_namespace, self.logger)
        self.assertEqual(subscription, expected)

    def test_valid_unsubscription(self):
        topic = "some/topic"
        expected = Unsubscription(topic)

        # without namespace
        event = broker.zeek.Event("unsubscribe", topic)
        unsubscription = map_management_message(
            event, self.module_namespace, self.logger
        )
        self.assertEqual(unsubscription, expected)

        # with namespace:
        event = broker.zeek.Event(self.module_namespace + "::unsubscribe", topic)
        unsubscription = map_management_message(
            event, self.module_namespace, self.logger
        )
        self.assertEqual(unsubscription, expected)
