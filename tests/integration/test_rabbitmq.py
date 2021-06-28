from dynaconf.utils.boxing import DynaBox
from datetime import datetime, timedelta
from multiprocessing import JoinableQueue
from stix2 import Indicator, Sighting
from threatbus_rabbitmq import plugin
from threatbus.data import (
    MessageType,
    SnapshotEnvelope,
    SnapshotRequest,
)
import time
import unittest


class TestRoundtrips(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # setup the backbone with a fan-in queue
        config = DynaBox(
            {
                "rabbitmq": {
                    "host": "localhost",
                    "port": 35672,
                    "username": "guest",
                    "password": "guest",
                    "vhost": "/",
                    "exchange_name": "threatbus",
                    "queue": {
                        "name_join_symbol": ".",
                        "name_suffix": "threatbus",
                        "durable": False,
                        "auto_delete": True,
                        "exclusive": False,
                        "lazy": False,
                        "max_items": 10,
                    },
                },
                "console": False,
                "file": False,
            }
        )

        cls.inq = JoinableQueue()
        plugin.run(config, config, cls.inq)

        # subscribe this test case as concumer
        cls.outq = JoinableQueue()
        plugin.subscribe("stix2/indicator", cls.outq)
        plugin.subscribe("stix2/sighting", cls.outq)
        plugin.subscribe("threatbus/snapshotrequest", cls.outq)
        plugin.subscribe("threatbus/snapshotenvelope", cls.outq)
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        plugin.stop()
        time.sleep(1)

    def setUp(self):
        self.ts = datetime.now().astimezone()
        self.ioc_id = "indicator--42d31a5b-2da0-4bdd-9823-1723a98fc2fb"
        self.ioc_value = "example.com"
        self.ioc = Indicator(
            id=self.ioc_id,
            pattern_type="stix",
            pattern=f"[domain-name:value = '{self.ioc_value}']",
        )

        self.sighting_context = {
            "ts": "2017-03-03T23:56:09.652643840",
            "uid": "CMeLkt11aTqwgN4FI9",
            "id.orig_h": "172.31.130.19",
            "id.orig_p": 43872,
            "id.resp_h": "172.31.129.17",
            "id.resp_p": 20004,
            "proto": "tcp",
            "service": None,
            "duration": 0.025249,
            "orig_bytes": 311,
            "resp_bytes": 999,
            "conn_state": "SF",
            "local_orig": None,
            "local_resp": None,
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 9,
            "orig_ip_bytes": 787,
            "resp_pkts": 7,
            "resp_ip_bytes": 1371,
            "tunnel_parents": [],
            "alert": {
                "signature": "VAST-RETRO Generic IoC match for: 172.31.129.17",
                "category": "Potentially Bad Traffic",
                "action": "allowed",
            },
            "event_type": "alert",
            "_extra": {"vast-ioc": "172.31.129.17"},
            "source": "VAST",
        }
        self.sighting = Sighting(sighting_of_ref=self.ioc_id)

        self.snapshot_id = "SNAPSHOT_UUID"
        self.snapshot = timedelta(days=42, hours=23, minutes=13, seconds=37)
        self.snapshot_request = SnapshotRequest(
            MessageType.SIGHTING, self.snapshot_id, self.snapshot
        )

        self.snapshot_envelope_indicator = SnapshotEnvelope(
            MessageType.INDICATOR, self.snapshot_id, self.ioc
        )
        self.snapshot_envelope_sighting = SnapshotEnvelope(
            MessageType.SIGHTING, self.snapshot_id, self.sighting
        )

    def test_intel_message_roundtrip(self):
        """
        Passes an Intel item to RabbitMQ and reads back the exact same item.
        """
        self.inq.put(self.ioc)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.ioc, out)

    def test_sighting_message_roundtrip(self):
        """
        Passes an Sighting item to RabbitMQ and reads back the exact same item.
        """
        self.inq.put(self.sighting)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.sighting, out)

    def test_snapshot_request_message_roundtrip(self):
        """
        Passes an SnapshotRequest item to RabbitMQ and reads back the exact same item.
        """
        self.inq.put(self.snapshot_request)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.snapshot_request, out)

    def test_snapshot_envelope_message_roundtrip(self):
        """
        Passes an SnapshotEnvelope item to RabbitMQ and reads back the exact same item.
        """
        self.inq.put(self.snapshot_envelope_indicator)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.snapshot_envelope_indicator, out)

        self.inq.put(self.snapshot_envelope_sighting)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.snapshot_envelope_sighting, out)
