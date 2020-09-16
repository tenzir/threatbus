import confuse
from datetime import datetime, timedelta
from plugins.backbones.threatbus_rabbitmq import plugin
from queue import Queue
from threatbus.data import (
    Intel,
    IntelData,
    IntelType,
    MessageType,
    Operation,
    Sighting,
    SnapshotEnvelope,
    SnapshotRequest,
)
import time
import unittest


class TestRoundtrips(unittest.TestCase):
    def setUp(self):
        self.ts = datetime.now().astimezone()
        self.intel_id = "intel-42"
        self.indicator = "6.6.6.6"
        self.intel_type = IntelType.IPSRC
        self.operation = Operation.ADD
        self.intel_data = IntelData(
            self.indicator, self.intel_type, foo=23, more_args="MORE ARGS"
        )
        self.intel = Intel(self.ts, self.intel_id, self.intel_data, self.operation)

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
        self.sighting = Sighting(self.ts, self.intel_id, self.sighting_context)

        self.snapshot_id = "SNAPSHOT_UUID"
        self.snapshot = timedelta(days=42, hours=23, minutes=13, seconds=37)
        self.snapshot_request = SnapshotRequest(
            MessageType.SIGHTING, self.snapshot_id, self.snapshot
        )

        self.snapshot_envelope_intel = SnapshotEnvelope(
            MessageType.INTEL, self.snapshot_id, self.intel
        )
        self.snapshot_envelope_sighting = SnapshotEnvelope(
            MessageType.SIGHTING, self.snapshot_id, self.sighting
        )

        # setup the backbone with a fan-in queue
        config = confuse.Configuration("threatbus")
        config["rabbitmq"].add({})
        config["rabbitmq"]["host"] = "localhost"
        config["rabbitmq"]["port"] = 35672
        config["rabbitmq"]["username"] = "guest"
        config["rabbitmq"]["password"] = "guest"
        config["rabbitmq"]["vhost"] = "/"
        config["rabbitmq"]["naming_join_pattern"] = "."
        config["rabbitmq"]["queue"].add({})
        config["rabbitmq"]["queue"]["durable"] = False
        config["rabbitmq"]["queue"]["auto_delete"] = True
        config["rabbitmq"]["queue"]["exclusive"] = False
        config["rabbitmq"]["queue"]["lazy"] = False
        config["rabbitmq"]["queue"]["max_items"] = 10
        config["console"] = False
        config["file"] = False

        self.inq = Queue()
        plugin.run(config, config, self.inq)

        # subscribe this test case as concumer
        self.outq = Queue()
        plugin.subscribe("threatbus/intel", self.outq)
        plugin.subscribe("threatbus/sighting", self.outq)
        plugin.subscribe("threatbus/snapshotrequest", self.outq)
        plugin.subscribe("threatbus/snapshotenvelope", self.outq)
        time.sleep(1)

    def test_intel_message_roundtrip(self):
        """
        Passes an Intel item to RabbitMQ and reads back the exact same item.
        """
        self.inq.put(self.intel)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.intel, out)

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
        self.inq.put(self.snapshot_envelope_intel)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.snapshot_envelope_intel, out)

        self.inq.put(self.snapshot_envelope_sighting)
        out = self.outq.get(timeout=10)  # raise after 10s without item
        self.assertEqual(self.snapshot_envelope_sighting, out)
