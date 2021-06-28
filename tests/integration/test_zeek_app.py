from dynaconf import Dynaconf
import os
import queue
from stix2 import Indicator, parse
import subprocess
import threading
from threatbus import start as start_threatbus
from threatbus.data import ThreatBusSTIX2Constants
import time
import unittest

from tests.utils import zmq_receiver, zmq_sender


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
        config = Dynaconf(
            settings_file="config_integration_test.yaml",
        )
        self.threatbus = start_threatbus(config)
        time.sleep(1)

    def tearDown(self):
        self.threatbus.stop()
        time.sleep(1)

    def test_intel_sighting_roundtrip(self):
        """
        Backend-agnostic roundtrip scenario, that starts a Zeek subprocess which
        activates the threatbus.zeek "app" script.
        The test sends an IoC with a malicious hostname via Threat Bus, using
        the ZMQ app plugin. Meanwhile, the Zeek subprocess reads a PCAP trace
        which contains exactly that malicious hostname from the IoC.
        If all goes well, Zeek subscribes to Threat Bus successfully, receives
        the IoC and hence reading the PCAP file results in a sighting. Zeek
        forwards that sighting to the Threat Bus Zeek plugin, where it is
        converted to a valid STIX-2 Sighting.
        The integration test subscribes a ZMQ receiver to the `stix2/sighting`
        topic and verifies all Zeek communication was handled correctly. I.e.,
        Zeek matched the IoC and reported the correct sighting.
        """
        # Start a ZMQ receiver that subscribes to the `stix2/sighting` topic and
        # forward exactly 1 item to a result queue
        result_q = queue.Queue()
        rec = threading.Thread(
            target=zmq_receiver.forward,
            args=(1, ["stix2/sighting"], result_q),
            daemon=True,
        )
        rec.start()

        # Spawn a Zeek subprocess that runs the `apps/zeek/threatbus.zeek`
        # script and reads a prepared PCAP trace that contains a network
        # connection to `example.com`
        zeek_process = RunZeek()
        if not zeek_process:
            self.fail("Error starting Zeek container.")

        # Let Zeek start up...
        time.sleep(1)

        # Send a new indicator (IoC) via the ZMQ test-util, which will be
        # forwarded to Zeek because Zeek subscribes to `stix2/indicator`
        ioc_id = "indicator--42d31a5b-2da0-4bdd-9823-1723a98fc2fb"
        ioc = Indicator(
            id=ioc_id,
            pattern_type="stix",
            pattern="[domain-name:value = 'example.com']",
        )
        zmq_sender.send("stix2/indicator", ioc.serialize(), port=13372, bind=False)

        # Wait for Zeek to ingest the IoC into its Intel framework, read the
        # PCAP trace and report back the sighting
        raw_msg = result_q.get(timeout=10)
        sighting = parse(raw_msg, allow_custom=True)
        result_q.task_done()

        self.assertIsNotNone(sighting)
        self.assertEqual(sighting.sighting_of_ref, ioc_id)
        self.assertTrue(
            ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value
            in sighting.object_properties()
        )
        self.assertEqual(sighting.x_threatbus_sighting_context, {"noisy": False})

        rec.join()
        result_q.join()
        zeek_process.kill()
        self.assertTrue(StopZeek())
