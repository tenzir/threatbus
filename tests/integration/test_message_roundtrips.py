import confuse
import queue
import threading
from threatbus import start
import time
import unittest

from tests.utils import zeek_receiver, zeek_sender


class TestMessageRoundtrip(unittest.TestCase):
    def setUp(self):
        config = confuse.Configuration("threatbus")
        config.set_file("config_integration_test.yaml")
        self.threatbus = threading.Thread(
            target=start,
            args=(config,),
            daemon=True,
        )
        self.threatbus.start()
        time.sleep(1)

    def test_zeek_plugin_message_roundtrip(self):
        """
        Backend agnostic message passing screnario. Sends a fixed amount of
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
