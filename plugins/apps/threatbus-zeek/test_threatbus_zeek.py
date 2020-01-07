import broker
from datetime import datetime
import unittest

import threatbus
from threatbus_zeek import map_to_internal, map_to_broker, validate_config


class TestMessageMapping(unittest.TestCase):
    def test_invalid_inputs(self):
        self.assertIsNone(map_to_broker(None))
        self.assertIsNone(map_to_broker(42))
        self.assertIsNone(map_to_broker(object))

    def test_valid_intel(self):
        ts = datetime.now()
        id = 42
        data = {"foo": 23}
        intel = threatbus.data.Intel(ts, id, data)
        broker_msg = map_to_broker(intel)
        self.assertEqual(broker_msg.name(), "intel")
        self.assertEqual(broker_msg.args(), [datetime.timestamp(ts), id, data])

    def test_valid_zeek_intel(self):
        ts = datetime.now()
        id = 42
        data = {"foo": 23}
        event = broker.zeek.Event("intel", datetime.timestamp(ts), id, data)
        intel = map_to_internal(event)
        self.assertEqual(type(intel), threatbus.data.Intel)
        self.assertEqual(intel.ts, ts)
        self.assertEqual(intel.id, id)
        self.assertEqual(intel.data, data)

    def test_valid_sighting(self):
        ts = datetime.now()
        intel_id = 42
        context = {"last_seen": 1234, "count": 13}
        sighting = threatbus.data.Sighting(ts, intel_id, context)
        broker_msg = map_to_broker(sighting)
        self.assertEqual(broker_msg.name(), "sighting")
        self.assertEqual(broker_msg.args(), [datetime.timestamp(ts), intel_id, context])

    def test_valid_zeek_sighting(self):
        ts = datetime.now()
        intel_id = 42
        context = {"last_seen": 1234, "count": 13}
        event = broker.zeek.Event("sighting", datetime.timestamp(ts), intel_id, context)
        sighting = map_to_internal(event)
        self.assertEqual(type(sighting), threatbus.data.Sighting)
        self.assertEqual(sighting.ts, ts)
        self.assertEqual(sighting.intel_id, intel_id)
        self.assertEqual(sighting.context, context)
