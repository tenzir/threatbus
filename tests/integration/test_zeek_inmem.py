from datetime import datetime
import broker
import os
import queue
import subprocess
import threading
import time
import unittest

from tests.utils import zeek_receiver, zeek_sender


def RunZeek():
    try:
        base = os.path.realpath(__file__)
        trace_file = os.path.join(
            os.path.dirname(base), "../resources/example.com-intel-sighting.pcap"
        )
        script_file = os.path.join(
            os.path.dirname(base), "../../apps/zeek/threatbus.zeek"
        )
        return subprocess.Popen(
            [
                "zeek",
                "-C",
                "-b",
                "--pseudo-realtime=0.5",
                "-r",
                trace_file,
                script_file,
                "--",
                "Tenzir::log_operations=F",
            ]
        )
    except subprocess.CalledProcessError:
        return False


class TestRoundtrips(unittest.TestCase):
    def test_zeek_plugin_message_roundtrip(self):
        """
            Backend agnostic message passing screnario. Sends a fixed amount of
            messages via the threatbus Zeek plugin, subscribes to threatbus, and
            checks if the initially sent messages can be retrieved back.
        """
        result_q = queue.Queue()
        items = 5
        rec = threading.Thread(
            target=zeek_receiver.forward, args=(items, result_q), daemon=False
        )
        rec.start()
        zeek_sender.send_generic(items)
        rec.join()

        self.assertEqual(result_q.qsize(), items)
        for _ in range(items):
            event = result_q.get()
            self.assertIsNotNone(event)
            result_q.task_done()
        self.assertEqual(0, result_q.qsize())
        result_q.join()

    def test_intel_sighting_roundtrip(self):
        """
            Backend agnostic routrip screnario, that starts invokes a Zeek
            subprocess. Zeek is started using the threatbus.zeek "app" script.
            The test sends an intelligence item via threatbus. The Zeek
            subprocess reads a PCAP trace which contains that known threat
            intelligence. The integration test subscribes to the sightings topic
            and verifies that Zeek reports sighted threat intelligence items.
        """

        # start a receiver that pushes exactly 1 item to a result queue
        result_q = queue.Queue()
        rec = threading.Thread(
            target=zeek_receiver.forward,
            args=(1, result_q, "tenzir/threatbus/sighting"),
            daemon=False,
        )
        rec.start()

        # spawn a zeek subprocess that uses the `apps/threatbus.zeek` script
        zeek_process = RunZeek()
        if not zeek_process:
            self.fail("Error starting Zeek. Is it installed?")

        time.sleep(1)

        # send a new intelligence item
        intel_id = "EXAMPLE.COM.IS.EVIL"
        data = {"indicator": "example.com", "intel_type": "DOMAIN"}
        intel = broker.zeek.Event("intel", datetime.now(), intel_id, data, "ADD")
        zeek_sender.send(intel)

        # wait for zeek to report sighting of the intel
        sighting = result_q.get(block=True)
        result_q.task_done()
        result_q.join()
        rec.join()
        zeek_process.kill()

        self.assertIsNotNone(sighting)
        name, args = sighting.name(), sighting.args()[0]
        self.assertEqual(len(args), 3)
        self.assertTrue(name.endswith("sighting"))
        self.assertTrue(type(args[0]).__name__ == "datetime")
        self.assertEqual(args[1], intel_id)
        self.assertEqual(args[2], {"noisy": False})
