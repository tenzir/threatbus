from dataclasses import dataclass
from datetime import timedelta
from enum import auto, Enum, unique
import json
from stix2 import Indicator, Sighting, parse
from stix2.parsing import dict_to_stix2
from typing import Union


@dataclass
class Subscription:
    topic: str
    snapshot: timedelta


@dataclass
class Unsubscription:
    topic: str


@unique
class Operation(Enum):
    EDIT = "EDIT"
    REMOVE = "REMOVE"


@unique
class MessageType(Enum):
    INDICATOR = auto()
    SIGHTING = auto()


@dataclass()
class Update:
    """
    An Update consists of at least an ID and Operation. The operation should be
    applied to items with the updated ID.
    TODO: specify content changes
    """

    id: str
    operation: Operation


@dataclass()
class SnapshotEnvelope:
    """
    SnapshotEnvelopes wrap indicators or sightings in response to
    SnapshotRequests. The envelope carries additional information, such as the
    MessageType and the unique ID of a snapshot.
    """

    snapshot_type: MessageType
    snapshot_id: str
    body: Union[Indicator, Sighting]


@dataclass
class SnapshotRequest:
    """
    Threat Bus creates SnapshotRequests when apps specifically ask for a
    snapshot during subscription. SnapshotRequests are provisioned through the
    backbones. A SnapshotRequest consists of the requested MessageType (either
    INDICATOR or SIGHTING), a unique ID, and the snapshot time delta (e.g., 5 days).
    """

    snapshot_type: MessageType
    snapshot_id: str
    snapshot: timedelta


class SnapshotRequestEncoder(json.JSONEncoder):
    """
    Encodes SnapshotRequest objects to JSON strings
    """

    def default(self, req: SnapshotRequest):
        if type(req) is not SnapshotRequest:
            # let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, req)
        return {
            "type": type(SnapshotRequest).__name__.lower(),
            "snapshot_type": int(req.snapshot_type.value),
            "snapshot_id": str(req.snapshot_id),
            "snapshot": int(req.snapshot.total_seconds()),
        }


class SnapshotRequestDecoder(json.JSONDecoder):
    """
    Decodes JSON strings to SnapshotRequest objects
    """

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.decode_hook, *args, **kwargs)

    def decode_hook(self, dct: dict):
        type_ = dct.get("type", None)
        if not type_ or type_ != type(SnapshotRequest).__name__.lower():
            return dct
        if "snapshot_type" in dct and "snapshot_id" in dct and "snapshot" in dct:
            return SnapshotRequest(
                MessageType(int(dct["snapshot_type"])),
                dct["snapshot_id"],
                timedelta(seconds=dct["snapshot"]),
            )


class SnapshotEnvelopeEncoder(json.JSONEncoder):
    """
    Encodes SnapshotEnvelope objects to JSON strings
    """

    def default(self, env: SnapshotEnvelope):
        if type(env) is not SnapshotEnvelope:
            # let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, env)
        return {
            "type": type(SnapshotEnvelope).__name__.lower(),
            "snapshot_type": int(env.snapshot_type.value),
            "snapshot_id": str(env.snapshot_id),
            "body": json.loads(
                env.body.serialize()
            ),  # read back json to avoid double serialization
        }


class SnapshotEnvelopeDecoder(json.JSONDecoder):
    """
    Decodes JSON strings to SnapshotEnvelope objects
    """

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.decode_hook, *args, **kwargs)

    def decode_hook(self, dct: dict):
        type_ = dct.get("type", None)
        if not type_:
            return dct
        if type_ != type(SnapshotEnvelope).__name__.lower():
            # decoders walk through nested objects first (bottom up).
            # try to parse nested stix2 objs per best-effort, else bubble up
            try:
                return dict_to_stix2(dct, allow_custom=True)
            except Exception:
                return dct
        return SnapshotEnvelope(
            MessageType(int(dct["snapshot_type"])),
            dct["snapshot_id"],
            parse(dct["body"], allow_custom=True),
        )
