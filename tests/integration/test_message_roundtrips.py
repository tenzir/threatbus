import confuse
from datetime import datetime
import json
import queue
import threading
from threatbus import start
from threatbus.data import (
    Intel,
    IntelData,
    IntelType,
    Operation,
    Sighting,
    IntelEncoder,
    IntelDecoder,
    SightingEncoder,
    SightingDecoder,
)
import time
import unittest

from tests.utils import zeek_receiver, zeek_sender, zmq_receiver, zmq_sender


class TestMessageRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TestMessageRoundtrip, cls).setUpClass()
        config = confuse.Configuration("threatbus")
        config.set_file("config_integration_test.yaml")
        cls.threatbus = threading.Thread(
            target=start,
            args=(config,),
            daemon=True,
        )
        cls.threatbus.start()
        time.sleep(1)

    def test_zeek_plugin_message_roundtrip(self):
        """
        Backend-agnostic message passing scenario. Sends a fixed amount of
        messages via the threatbus Zeek plugin, subscribes to Threat Bus, and
        checks if the initially sent messages can be retrieved back.
        """
        result_q = queue.Queue()
        items = 5
        rec = threading.Thread(
            target=zeek_receiver.forward, args=(items, result_q), daemon=False
        )
        rec.start()
        zeek_sender.send_generic("threatbus/intel", items)
        time.sleep(1)
        self.assertEqual(result_q.qsize(), items)
        for _ in range(items):
            event = result_q.get(timeout=1)
            self.assertIsNotNone(event)
            result_q.task_done()
        self.assertEqual(0, result_q.qsize())
        result_q.join()

    def test_zmq_app_plugin_message_roundtrip(self):
        """
        Backend-agnostic message passing scenario. Sends a fixed amount of
        messages via the threatbus ZeroMQ app plugin, subscribes to Threat Bus,
        and checks if the initially sent messages can be retrieved back.
        """
        result_q = queue.Queue()
        items = 2
        topics = ["threatbus/intel", "threatbus/sighting"]
        rec = threading.Thread(
            target=zmq_receiver.forward, args=(items, topics, result_q), daemon=False
        )
        rec.start()
        ts = datetime.now()
        intel_id = "intel_42"
        intel = Intel(
            ts, intel_id, IntelData("6.6.6.6", IntelType.IPSRC), Operation.ADD
        )
        zmq_sender.send(
            "threatbus/intel",
            json.dumps(intel, cls=IntelEncoder),
            port=13372,
            bind=False,
        )
        sighting = Sighting(ts, intel_id, {}, ("6.6.6.6",))
        zmq_sender.send(
            "threatbus/sighting",
            json.dumps(sighting, cls=SightingEncoder),
            port=13372,
            bind=False,
        )
        time.sleep(1)
        self.assertEqual(result_q.qsize(), items)

        event = result_q.get(timeout=1)
        self.assertIsNotNone(event)
        self.assertEqual(json.loads(event, cls=IntelDecoder), intel)
        result_q.task_done()

        event = result_q.get(timeout=1)
        self.assertIsNotNone(event)
        self.assertEqual(json.loads(event, cls=SightingDecoder), sighting)
        result_q.task_done()

        self.assertEqual(0, result_q.qsize())
        result_q.join()
        rec.join(timeout=1)
