from datetime import datetime, timedelta
import unittest
import json

from stix2 import Indicator, Sighting
from stix2.utils import format_datetime

from data import (
    MessageType,
    Operation,
    SnapshotEnvelope,
    SnapshotRequest,
    SnapshotRequestEncoder,
    SnapshotRequestDecoder,
    SnapshotEnvelopeEncoder,
    SnapshotEnvelopeDecoder,
    ThreatBusSTIX2Constants,
)


class TestJsonConversions(unittest.TestCase):
    def setUp(self):
        self.created = datetime.now().astimezone()
        self.indicator_id = "indicator--df0f9a0e-c3b6-4f53-b0cf-5e9c454ee0cc"
        self.pattern = "[ipv4-addr:value = '6.6.6.6']"
        self.pattern_type = "stix2"
        self.operation = Operation.REMOVE
        self.indicator = Indicator(
            id=self.indicator_id,
            pattern=self.pattern,
            pattern_type=self.pattern_type,
            created=self.created,
            valid_from=self.created,
            modified=self.created,
        )

        self.sighting_source = "VAST"
        self.sighting_id = "sighting--df0f9a0e-c3b6-4f53-b0cf-5e9c454ee0cc"
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
        }
        self.sighting = Sighting(
            id=self.sighting_id,
            created=self.created,
            modified=self.created,
            sighting_of_ref=self.indicator_id,
            custom_properties={
                ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value: self.sighting_context,
                ThreatBusSTIX2Constants.X_THREATBUS_INDICATOR.value: self.indicator,
                ThreatBusSTIX2Constants.X_THREATBUS_SOURCE.value: self.sighting_source,
            },
        )

        self.snapshot_id = "SNAPSHOT_UUID"
        self.snapshot = timedelta(days=42, hours=23, minutes=13, seconds=37)
        self.snapshot_request = SnapshotRequest(
            MessageType.SIGHTING, self.snapshot_id, self.snapshot
        )

        self.snapshot_envelope_indicator = SnapshotEnvelope(
            MessageType.INDICATOR, self.snapshot_id, self.indicator
        )
        self.snapshot_envelope_sighting = SnapshotEnvelope(
            MessageType.SIGHTING, self.snapshot_id, self.sighting
        )

    def test_valid_snapshot_request_encoding(self):
        encoded = json.dumps(self.snapshot_request, cls=SnapshotRequestEncoder)
        # encoding cannot be compared as string, because order of the fileds in
        # the string representation is not fixed.
        # We cast the JSON back to a simple python dict and them compare values
        py_dict = json.loads(encoded)
        self.assertEqual(py_dict["snapshot_type"], MessageType.SIGHTING.value)
        self.assertEqual(py_dict["snapshot_id"], self.snapshot_id)
        self.assertEqual(py_dict["snapshot"], self.snapshot.total_seconds())
        self.assertEqual(py_dict["type"], SnapshotRequest.__name__.lower())

    def test_valid_snapshot_request_decoding(self):
        encoded = f"""{{
            "type": "{SnapshotRequest.__name__.lower()}",
            "snapshot_type": {MessageType.SIGHTING.value},
            "snapshot_id": "{self.snapshot_id}",
            "snapshot": {self.snapshot.total_seconds()}
        }}"""
        read_back = json.loads(encoded, cls=SnapshotRequestDecoder)
        self.assertEqual(read_back, self.snapshot_request)

    def test_snapshot_request_encoding_roundtrip(self):
        encoded = json.dumps(self.snapshot_request, cls=SnapshotRequestEncoder)
        read_back = json.loads(encoded, cls=SnapshotRequestDecoder)
        self.assertEqual(read_back, self.snapshot_request)

    def test_valid_snapshot_envelope_encoding(self):
        encoded_envelope_indicator = json.dumps(
            self.snapshot_envelope_indicator, cls=SnapshotEnvelopeEncoder
        )
        encoded_envelope_sighting = json.dumps(
            self.snapshot_envelope_sighting, cls=SnapshotEnvelopeEncoder
        )
        # encoding cannot be compared as string, because order of the fileds in
        # the string representation is not fixed.
        # We cast the JSON back to a simple python dict and them compare values
        py_dict = json.loads(encoded_envelope_indicator)
        self.assertEqual(py_dict["snapshot_type"], MessageType.INDICATOR.value)
        self.assertEqual(py_dict["snapshot_id"], self.snapshot_id)
        self.assertEqual(py_dict["body"]["created"], format_datetime(self.created))
        self.assertEqual(py_dict["body"]["id"], self.indicator_id)
        self.assertEqual(py_dict["body"]["pattern"], self.pattern)
        self.assertEqual(py_dict["body"]["pattern_type"], self.pattern_type)
        self.assertEqual(py_dict["type"], SnapshotEnvelope.__name__.lower())

        py_dict = json.loads(encoded_envelope_sighting)
        self.assertEqual(py_dict["snapshot_type"], MessageType.SIGHTING.value)
        self.assertEqual(py_dict["snapshot_id"], self.snapshot_id)
        self.assertEqual(py_dict["body"]["created"], format_datetime(self.created))
        self.assertEqual(py_dict["body"]["sighting_of_ref"], self.indicator_id)
        self.assertEqual(
            py_dict["body"][ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value],
            self.sighting_context,
        )
        self.assertEqual(py_dict["type"], SnapshotEnvelope.__name__.lower())

    def test_valid_snapshot_envelope_decoding(self):
        encoded_envelope_indicator = f"""{{
            "type": "{SnapshotEnvelope.__name__.lower()}",
            "snapshot_type": {MessageType.INDICATOR.value},
            "snapshot_id": "{self.snapshot_id}",
            "body": {{
                "id": "{self.indicator_id}",
                "pattern": "{self.pattern}",
                "pattern_type": "stix2",
                "created": "{format_datetime(self.created)}",
                "type": "indicator",
                "spec_version": "2.1",
                "modified": "{format_datetime(self.created)}",
                "valid_from": "{format_datetime(self.created)}"
            }}
        }}"""
        read_back = json.loads(encoded_envelope_indicator, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_indicator)

        encoded_envelope_sighting = f"""{{
            "type": "{SnapshotEnvelope.__name__.lower()}",
            "snapshot_type": {MessageType.SIGHTING.value},
            "snapshot_id": "{self.snapshot_id}",
            "body": {{
                "created": "{format_datetime(self.created)}",
                "modified": "{format_datetime(self.created)}",
                "sighting_of_ref": "{self.indicator_id}",
                "type": "sighting",
                "spec_version": "2.1",
                "id": "{self.sighting_id}",
                "{ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value}": {json.dumps(self.sighting_context)},
                "{ThreatBusSTIX2Constants.X_THREATBUS_INDICATOR.value}": {self.indicator.serialize()},
                "{ThreatBusSTIX2Constants.X_THREATBUS_SOURCE.value}": "{self.sighting_source}"
            }}
        }}"""
        read_back = json.loads(encoded_envelope_sighting, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_sighting)

    def test_snapshot_envelope_encoding_roundtrip(self):
        encoded = json.dumps(
            self.snapshot_envelope_indicator, cls=SnapshotEnvelopeEncoder
        )
        read_back = json.loads(encoded, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_indicator)

        encoded = json.dumps(
            self.snapshot_envelope_sighting, cls=SnapshotEnvelopeEncoder
        )
        read_back = json.loads(encoded, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_sighting)
