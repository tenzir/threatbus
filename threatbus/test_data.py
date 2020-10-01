from datetime import datetime, timedelta
import unittest
import json

from data import (
    Intel,
    IntelData,
    IntelType,
    MessageType,
    Operation,
    Sighting,
    SnapshotEnvelope,
    SnapshotRequest,
    IntelEncoder,
    IntelDecoder,
    SightingEncoder,
    SightingDecoder,
    SnapshotRequestEncoder,
    SnapshotRequestDecoder,
    SnapshotEnvelopeEncoder,
    SnapshotEnvelopeDecoder,
)


class TestJsonConversions(unittest.TestCase):
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
        self.sighting = Sighting(
            self.ts, self.intel_id, self.sighting_context, (self.indicator,)
        )

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

    def test_valid_intel_encoding(self):
        encoded = json.dumps(self.intel, cls=IntelEncoder)
        # encoding cannot be compared as string, because order of the fileds in
        # the string representation is not fixed.
        # We cast the JSON back to a simple python dict and them compare values
        py_dict = json.loads(encoded)
        self.assertEqual(py_dict["ts"], str(self.ts))
        self.assertEqual(py_dict["id"], self.intel_id)
        self.assertEqual(
            py_dict["data"],
            {
                "foo": 23,
                "more_args": "MORE ARGS",
                "indicator": [self.indicator],
                "intel_type": self.intel_type.value,
            },
        )

    def test_valid_intel_decoding(self):
        encoded = f'{{"ts": "{self.ts}", "id": "intel-42", "data": {{"foo": 23, "more_args": "MORE ARGS", "indicator": ["{self.indicator}"], "intel_type": "{self.intel_type.value}"}}, "operation": "{self.operation.value}"}}'
        intel = json.loads(encoded, cls=IntelDecoder)
        self.assertEqual(intel, self.intel)

    def test_intel_encoding_roundtrip(self):
        encoded = json.dumps(self.intel, cls=IntelEncoder)
        read_back = json.loads(encoded, cls=IntelDecoder)
        self.assertEqual(read_back, self.intel)

    def test_valid_sighting_encoding(self):
        encoded = json.dumps(self.sighting, cls=SightingEncoder)
        # encoding cannot be compared as string, because order of the fileds in
        # the string representation is not fixed.
        # We cast the JSON back to a simple python dict and them compare values
        py_dict = json.loads(encoded)
        self.assertEqual(py_dict["ts"], str(self.ts))
        self.assertEqual(py_dict["intel"], self.intel_id)
        self.assertEqual(py_dict["ioc"], [self.indicator])
        self.assertEqual(py_dict["context"], self.sighting_context)

    def test_valid_sighting_decoding(self):
        encoded = f'{{"ts": "{self.ts}", "intel": "{self.intel_id}", "ioc": ["{self.indicator}"], "context": {json.dumps(self.sighting_context)}}}'
        sighting = json.loads(encoded, cls=SightingDecoder)
        self.assertEqual(sighting, self.sighting)

    def test_sighting_encoding_roundtrip(self):
        encoded = json.dumps(self.sighting, cls=SightingEncoder)
        read_back = json.loads(encoded, cls=SightingDecoder)
        self.assertEqual(read_back, self.sighting)

    def test_valid_snapshot_request_encoding(self):
        encoded = json.dumps(self.snapshot_request, cls=SnapshotRequestEncoder)
        # encoding cannot be compared as string, because order of the fileds in
        # the string representation is not fixed.
        # We cast the JSON back to a simple python dict and them compare values
        py_dict = json.loads(encoded)
        self.assertEqual(py_dict["snapshot_type"], MessageType.SIGHTING.value)
        self.assertEqual(py_dict["snapshot_id"], self.snapshot_id)
        self.assertEqual(py_dict["snapshot"], self.snapshot.total_seconds())

    def test_valid_snapshot_request_decoding(self):
        encoded = f'{{"snapshot_type": {MessageType.SIGHTING.value}, "snapshot_id": "{self.snapshot_id}", "snapshot": {self.snapshot.total_seconds()}}}'
        read_back = json.loads(encoded, cls=SnapshotRequestDecoder)
        self.assertEqual(read_back, self.snapshot_request)

    def test_snapshot_request_encoding_roundtrip(self):
        encoded = json.dumps(self.snapshot_request, cls=SnapshotRequestEncoder)
        read_back = json.loads(encoded, cls=SnapshotRequestDecoder)
        self.assertEqual(read_back, self.snapshot_request)

    def test_valid_snapshot_envelope_encoding(self):
        encoded_envelope_intel = json.dumps(
            self.snapshot_envelope_intel, cls=SnapshotEnvelopeEncoder
        )
        encoded_envelope_sighting = json.dumps(
            self.snapshot_envelope_sighting, cls=SnapshotEnvelopeEncoder
        )
        # encoding cannot be compared as string, because order of the fileds in
        # the string representation is not fixed.
        # We cast the JSON back to a simple python dict and them compare values
        py_dict = json.loads(encoded_envelope_intel)
        self.assertEqual(py_dict["snapshot_type"], MessageType.INTEL.value)
        self.assertEqual(py_dict["snapshot_id"], self.snapshot_id)
        self.assertEqual(py_dict["body"]["ts"], str(self.ts))
        self.assertEqual(py_dict["body"]["id"], self.intel_id)
        self.assertEqual(py_dict["body"]["operation"], self.operation.value)
        self.assertEqual(py_dict["body"]["data"]["indicator"][0], self.indicator)
        self.assertEqual(py_dict["body"]["data"]["intel_type"], self.intel_type.value)

        py_dict = json.loads(encoded_envelope_sighting)
        self.assertEqual(py_dict["snapshot_type"], MessageType.SIGHTING.value)
        self.assertEqual(py_dict["snapshot_id"], self.snapshot_id)
        self.assertEqual(py_dict["body"]["ts"], str(self.ts))
        self.assertEqual(py_dict["body"]["intel"], self.intel_id)
        self.assertEqual(py_dict["body"]["ioc"], [self.indicator])
        self.assertEqual(py_dict["body"]["context"], self.sighting_context)

    def test_valid_snapshot_envelope_decoding(self):
        encoded_envelope_intel = f'{{"snapshot_type": {MessageType.INTEL.value}, "snapshot_id": "{self.snapshot_id}", "body": {{"ts": "{self.ts}", "id": "{self.intel_id}", "data": {{"foo": 23, "more_args": "MORE ARGS", "indicator": ["{self.indicator}"], "intel_type": "{self.intel_type.value}"}}, "operation": "{self.operation.value}"}}}}'
        read_back = json.loads(encoded_envelope_intel, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_intel)

        encoded_envelope_sighting = f'{{"snapshot_type": {MessageType.SIGHTING.value}, "snapshot_id": "{self.snapshot_id}", "body": {{"ts": "{self.ts}", "intel": "{self.intel_id}", "ioc": ["{self.indicator}"], "context": {json.dumps(self.sighting_context)}}}}}'
        read_back = json.loads(encoded_envelope_sighting, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_sighting)

    def test_snapshot_envelope_encoding_roundtrip(self):
        encoded = json.dumps(self.snapshot_envelope_intel, cls=SnapshotEnvelopeEncoder)
        read_back = json.loads(encoded, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_intel)

        encoded = json.dumps(
            self.snapshot_envelope_sighting, cls=SnapshotEnvelopeEncoder
        )
        read_back = json.loads(encoded, cls=SnapshotEnvelopeDecoder)
        self.assertEqual(read_back, self.snapshot_envelope_sighting)
