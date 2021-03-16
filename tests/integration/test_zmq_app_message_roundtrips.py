import confuse
import queue
import threading
from stix2 import Indicator, parse, Sighting
from threatbus import start as start_threatbus
import time
import unittest

from tests.utils import zmq_receiver, zmq_sender


class TestZmqMessageRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TestZmqMessageRoundtrip, cls).setUpClass()
        config = confuse.Configuration("threatbus")
        config.set_file("config_integration_test.yaml")
        cls.threatbus = start_threatbus(config)
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.threatbus.stop()
        time.sleep(1)

    def test_zmq_app_plugin_message_roundtrip(self):
        """
        Backend-agnostic message passing scenario. Sends a fixed amount of
        messages via the threatbus ZeroMQ app plugin, subscribes to Threat Bus,
        and checks if the initially sent messages can be retrieved back.
        """
        result_q = queue.Queue()
        items = 2
        topics = ["stix2/indicator", "stix2/sighting"]
        rec = threading.Thread(
            target=zmq_receiver.forward, args=(items, topics, result_q), daemon=False
        )
        rec.start()
        ioc = Indicator(pattern_type="stix", pattern="[ipv4-addr:value = '6.6.6.6']")
        zmq_sender.send(
            "stix2/indicator",
            ioc.serialize(),
            port=13372,
            bind=False,
        )
        sighting = Sighting(sighting_of_ref=ioc.id)
        zmq_sender.send(
            "stix2/sighting",
            sighting.serialize(),
            port=13372,
            bind=False,
        )
        time.sleep(1)
        self.assertEqual(result_q.qsize(), items)

        event = result_q.get(timeout=1)
        self.assertIsNotNone(event)
        self.assertEqual(parse(event), ioc)
        result_q.task_done()

        event = result_q.get(timeout=1)
        self.assertIsNotNone(event)
        self.assertEqual(parse(event), sighting)
        result_q.task_done()

        self.assertEqual(0, result_q.qsize())
        result_q.join()
        rec.join(timeout=1)
