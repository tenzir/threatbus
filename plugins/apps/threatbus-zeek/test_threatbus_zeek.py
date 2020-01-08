import broker
from datetime import datetime, timezone
import unittest

import threatbus
from threatbus.data import Intel, Operation, Sighting
from threatbus_zeek import map_to_internal, map_to_broker, map_to_string_set


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.ts = datetime.now(timezone.utc).astimezone()
        self.id = "42"

    def test_invalid_inputs(self):
        self.assertIsNone(map_to_broker(None))
        self.assertIsNone(map_to_broker(42))
        self.assertIsNone(map_to_broker(object))

    def test_valid_intel(self):
        data = {"foo": 23}
        op = Operation.REMOVE
        intel = Intel(self.ts, self.id, data, op)
        broker_msg = map_to_broker(intel)
        self.assertEqual(broker_msg.name(), "Tenzir::update_intel")
        self.assertEqual(broker_msg.args(), [(self.ts, self.id, data, op.value)])

    def test_valid_zeek_intel(self):
        data = {"foo": 23}
        op = Operation.REMOVE
        event = broker.zeek.Event("intel", self.ts, self.id, data, op.value)
        intel = map_to_internal(event)
        self.assertEqual(type(intel), Intel)
        self.assertEqual(intel.ts, self.ts)
        self.assertEqual(intel.id, self.id)
        self.assertEqual(intel.data, data)
        self.assertEqual(intel.operation, op)

    def test_valid_sighting(self):
        context = {"last_seen": 1234, "count": 13}
        sighting = Sighting(self.ts, self.id, context)
        broker_msg = map_to_broker(sighting)
        self.assertEqual(broker_msg.name(), "Tenzir::update_sighting")
        self.assertEqual(broker_msg.args(), [(self.ts, self.id, context)])

    def test_valid_zeek_sighting(self):
        context = {"last_seen": 1234, "count": 13}
        event = broker.zeek.Event("sighting", self.ts, self.id, context)
        sighting = map_to_internal(event)
        self.assertEqual(type(sighting), Sighting)
        self.assertEqual(sighting.ts, self.ts)
        self.assertEqual(sighting.intel_id, self.id)
        self.assertEqual(sighting.context, context)

    def test_default_intel_operation(self):
        event = broker.zeek.Event("intel", self.ts, 0, {})
        intel = map_to_internal(event)
        self.assertEqual(intel.operation, Operation.ADD)

        event = broker.zeek.Event("intel", self.ts, 0, {}, "INVALID")
        intel = map_to_internal(event)
        self.assertEqual(intel.operation, Operation.ADD)


class TestTopicMapping(unittest.TestCase):
    def test_invalid_inputs(self):
        self.assertEqual(map_to_string_set(None), set())
        self.assertEqual(map_to_string_set("Foo"), set())
        self.assertEqual(map_to_string_set(object), set())

    def test_valid_topics(self):
        vt = broker._broker.VectorTopic([broker.Topic("foo"), broker.Topic("bar")])
        self.assertEqual(map_to_string_set(vt), {"foo", "bar"})
