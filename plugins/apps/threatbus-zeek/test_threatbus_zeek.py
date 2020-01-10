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
        self.module_namespace = "TestNamespace"

    def test_invalid_inputs(self):
        self.assertIsNone(map_to_broker(None, None))
        self.assertIsNone(map_to_broker(None, ""))
        self.assertIsNone(map_to_broker(None, self.module_namespace))
        self.assertIsNone(map_to_broker(42, self.module_namespace))
        self.assertIsNone(map_to_broker(object, self.module_namespace))

    def test_invalid_zeek_inputs(self):
        broker_data = broker.zeek.Event("Hello")
        self.assertIsNone(map_to_internal(broker_data, None))
        self.assertIsNone(map_to_internal(broker_data, self.module_namespace))

        # not enough arguments provided
        broker_data = broker.zeek.Event("sighting", 1, 2)
        self.assertIsNone(map_to_internal(broker_data, None))
        self.assertIsNone(map_to_internal(broker_data, self.module_namespace))

        broker_data = broker.zeek.Event("intel", 42, {},)
        self.assertIsNone(map_to_internal(broker_data, None))
        self.assertIsNone(map_to_internal(broker_data, self.module_namespace))

    def test_valid_intel(self):
        data = {"foo": 23}
        op = Operation.REMOVE
        intel = Intel(self.ts, self.id, data, op)
        broker_msg = map_to_broker(intel, self.module_namespace)
        self.assertEqual(broker_msg.name(), self.module_namespace + "::intel")
        self.assertEqual(broker_msg.args(), [(self.ts, self.id, data, op.value)])

    def test_valid_zeek_intel(self):
        data = {"foo": 23}
        op = Operation.REMOVE
        # without namespace:
        event = broker.zeek.Event("intel", self.ts, self.id, data, op.value)
        intel = map_to_internal(event, self.module_namespace)
        self.assertEqual(type(intel), Intel)
        self.assertEqual(intel.ts, self.ts)
        self.assertEqual(intel.id, self.id)
        self.assertEqual(intel.data, data)
        self.assertEqual(intel.operation, op)

        # with namespace:
        event = broker.zeek.Event(
            self.module_namespace + "::intel", self.ts, self.id, data, op.value
        )
        intel_ns = map_to_internal(event, self.module_namespace)
        self.assertEqual(intel, intel_ns)

    def test_valid_sighting(self):
        context = {"last_seen": 1234, "count": 13}
        sighting = Sighting(self.ts, self.id, context)
        broker_msg = map_to_broker(sighting, self.module_namespace)
        self.assertEqual(broker_msg.name(), self.module_namespace + "::sighting")
        self.assertEqual(broker_msg.args(), [(self.ts, self.id, context)])

    def test_valid_zeek_sighting(self):
        context = {"last_seen": 1234, "count": 13}
        # without namespace:
        event = broker.zeek.Event("sighting", self.ts, self.id, context)
        sighting = map_to_internal(event, self.module_namespace)
        self.assertEqual(type(sighting), Sighting)
        self.assertEqual(sighting.ts, self.ts)
        self.assertEqual(sighting.intel, self.id)
        self.assertEqual(sighting.context, context)

        # with namespace:
        event = broker.zeek.Event(
            self.module_namespace + "::sighting", self.ts, self.id, context
        )
        sighting_ns = map_to_internal(event, self.module_namespace)
        self.assertEqual(sighting, sighting_ns)

    def test_default_intel_operation(self):
        event = broker.zeek.Event("intel", self.ts, 0, {})
        intel = map_to_internal(event, self.module_namespace)
        self.assertEqual(intel.operation, Operation.ADD)

        event = broker.zeek.Event("intel", self.ts, 0, {}, "INVALID")
        intel = map_to_internal(event, self.module_namespace)
        self.assertEqual(intel.operation, Operation.ADD)


class TestTopicMapping(unittest.TestCase):
    def test_invalid_inputs(self):
        self.assertEqual(map_to_string_set(None), set())
        self.assertEqual(map_to_string_set("Foo"), set())
        self.assertEqual(map_to_string_set(object), set())

    def test_valid_topics(self):
        vt = broker._broker.VectorTopic([broker.Topic("foo"), broker.Topic("bar")])
        self.assertEqual(map_to_string_set(vt), {"foo", "bar"})
