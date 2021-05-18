from dataclasses import dataclass
from datetime import timedelta
from enum import auto, Enum, unique
import json
from stix2 import Indicator, Sighting, parse
from stix2.parsing import dict_to_stix2
from typing import List, Union

## Threat Bus custom STIX-2 attributes
@unique
class ThreatBusSTIX2Constants(Enum):
    # used in Sighting.custom_properties to reference the full STIX-2 Indicator
    X_THREATBUS_INDICATOR = "x_threatbus_indicator"
    # used in Sighting.custom_properties to reference the Indicator value, in
    # case the full indicator is not present any more.
    X_THREATBUS_INDICATOR_VALUE = "x_threatbus_indicator_value"
    # used in Sighting.custom_properties.context
    X_THREATBUS_SOURCE = "x_threatbus_source"
    X_THREATBUS_SIGHTING_CONTEXT = "x_threatbus_sighting_context"
    # Indicates an update operation for the STIX-2 item. See Operation enum.
    X_THREATBUS_UPDATE = "x_threatbus_update"


@dataclass
class Subscription:
    # either a single topic or a list of topics, e.g., `stix2/indicator`
    topic: Union[str, List[str]]
    snapshot: timedelta


@dataclass
class Unsubscription:
    # the p2p_topic used for point-to-point communication between the host and
    # the subscriber, not a human-readable topic. I.e., the random string that
    # was sent as respons from the Threat Bus host during subscription.
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
            "type": SnapshotRequest.__name__.lower(),
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
        if not type_ or type_ != SnapshotRequest.__name__.lower():
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
            "type": SnapshotEnvelope.__name__.lower(),
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
        if type_ != SnapshotEnvelope.__name__.lower():
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
