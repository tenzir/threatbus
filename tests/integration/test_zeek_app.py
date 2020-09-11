import broker
import confuse
from datetime import datetime
import os
import queue
import subprocess
import threading
from threatbus import start
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
                "docker",
                "run",
                "--net=host",
                "--rm",
                "--name=zeek-int",
                "-v",
                f"{trace_file}:/trace.pcap",
                "-v",
                f"{script_file}:/opt/zeek/share/zeek/site/threatbus.zeek",
                "fixel/zeek:latest",
                "-C",
                "--pseudo-realtime=0.5",
                "-r",
                "/trace.pcap",
                "/opt/zeek/share/zeek/site/threatbus.zeek",
                "--",
                "Tenzir::log_operations=F",
            ]
        )
    except subprocess.CalledProcessError:
        return False


def StopZeek():
    try:
        return subprocess.Popen(
            [
                "docker",
                "kill",
                "zeek-int",
            ]
        )
    except subprocess.CalledProcessError:
        return False


class TestZeekSightingReports(unittest.TestCase):
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

    def test_intel_sighting_roundtrip(self):
        """
        Backend agnostic routrip screnario, that starts a Zeek
        subprocess. Zeek is started using the threatbus.zeek "app" script.
        The test sends an intelligence item via Threat Bus. The Zeek
        subprocess reads a PCAP trace which contains that known threat
        intelligence. The integration test subscribes to the sightings topic
        and verifies that Zeek reports sighted threat intelligence back.
        """
        # start a receiver that pushes exactly 1 item to a result queue
        result_q = queue.Queue()
        rec = threading.Thread(
            target=zeek_receiver.forward,
            args=(1, result_q, "threatbus/sighting"),
            daemon=True,
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
        zeek_sender.send("threatbus/intel", intel)

        # wait for zeek to report sighting of the intel
        sighting = result_q.get(timeout=10)
        result_q.task_done()
        zeek_process.kill()

        self.assertIsNotNone(sighting)
        name, args = sighting.name(), sighting.args()[0]
        self.assertEqual(len(args), 3)
        self.assertTrue(name.endswith("sighting"))
        self.assertTrue(type(args[0]).__name__ == "datetime")
        self.assertEqual(args[1], intel_id)
        self.assertEqual(args[2], {"noisy": False})

        rec.join()
        result_q.join()
        self.assertTrue(StopZeek())
