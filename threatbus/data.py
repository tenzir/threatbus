import copy
from dataclasses import dataclass
from datetime import datetime, timedelta
from dateutil import parser
from enum import auto, Enum, unique
import json
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
    ADD = "ADD"
    REMOVE = "REMOVE"


@unique
class MessageType(Enum):
    INTEL = auto()
    SIGHTING = auto()


@unique
class IntelType(Enum):
    IPSRC = auto()
    IPDST = auto()
    IPSRC_PORT = auto()
    IPDST_PORT = auto()
    EMAILSRC = auto()
    EMAILDST = auto()
    TARGETEMAIL = auto()
    EMAILATTACHMENT = auto()
    FILENAME = auto()
    HOSTNAME = auto()
    DOMAIN = auto()
    DOMAIN_IP = auto()
    URL = auto()
    URI = auto()
    USERAGENT = auto()
    MD5 = auto()
    MALWARESAMPLE = auto()
    FILENAME_MD5 = auto()
    SHA1 = auto()
    FILENAME_SHA1 = auto()
    SHA256 = auto()
    FILENAME_SHA256 = auto()
    X509FINGERPRINTSHA1 = auto()
    PDB = auto()
    AUTHENTIHASH = auto()
    SSDEEP = auto()
    IMPHASH = auto()
    PEHASH = auto()
    IMPFUZZY = auto()
    SHA224 = auto()
    SHA384 = auto()
    SHA512 = auto()
    SHA512_224 = auto()
    SHA512_256 = auto()
    TLSH = auto()
    CDHASH = auto()
    FILENAME_AUTHENTIHASH = auto()
    FILENAME_SSDEEP = auto()
    FILENAME_IMPHASH = auto()
    FILENAME_PEHASH = auto()
    FILENAME_IMPFUZZY = auto()
    FILENAME_SHA224 = auto()
    FILENAME_SHA384 = auto()
    FILENAME_SHA512 = auto()
    FILENAME_SHA512_224 = auto()
    FILENAME_SHA512_256 = auto()
    FILENAME_TLSH = auto()


class IntelData(dict):
    """Threat Bus intel data is a dictionary with at least two keys: 'indicator' and 'intel_type'.
    The 'indicator' is a tuple of strings, defining the IoC(s)
    The 'intel_type' is a threatbus.data.IntelType
    """

    def __init__(
        self, indicator: Union[str, tuple], intel_type: IntelType, *args, **kw
    ):
        super(IntelData, self).__init__(*args, **kw)
        assert indicator, "Intel indicator must be set"
        assert (
            isinstance(indicator, tuple)
            and all(map(lambda e: isinstance(e, str), indicator))
            or isinstance(indicator, str)
        ), "Intel indicator must either be a string or tuple of strings"
        assert intel_type, "Intel type must be set"
        assert isinstance(
            intel_type, IntelType
        ), "Intel type must be of type threatbus.data.IntelType"
        self["indicator"] = indicator if isinstance(indicator, tuple) else (indicator,)
        self["intel_type"] = intel_type


@dataclass()
class Intel:
    ts: datetime
    id: str
    data: IntelData
    operation: Operation


@dataclass()
class Sighting:
    ts: datetime
    intel: str
    context: dict
    ioc: Union[tuple, None]


@dataclass()
class SnapshotEnvelope:
    """
    SnapshotEnvelopes are used to wrap intel items or sightings in response to
    SnapshotRequests. The envelope carries additional information, such as the
    MessageType and the unique ID of a snapshot.
    """

    snapshot_type: MessageType
    snapshot_id: str
    body: Union[Intel, Sighting]


@dataclass
class SnapshotRequest:
    """
    Threat Bus creates SnapshotRequests when apps specifically as for a snapshot
    during subscription. SnapshotRequests are provisioned via the backbones.
    A request consists of the requested MessageType (either INTEL or SIGHTING),
    a unique ID, and the snapshot time delta (e.g., 30 days).
    """

    snapshot_type: MessageType
    snapshot_id: str
    snapshot: timedelta


class IntelEncoder(json.JSONEncoder):
    """
    Encodes Intel objects to JSON strings
    """

    def default(self, intel: Intel):
        if type(intel) is not Intel:
            # let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, intel)
        data = copy.deepcopy(intel.data)
        data["indicator"] = list(intel.data["indicator"])
        data["intel_type"] = int(intel.data["intel_type"].value)
        return {
            "ts": str(intel.ts),
            "id": str(intel.id),
            "data": data,
            "operation": str(intel.operation.value),
        }


class IntelDecoder(json.JSONDecoder):
    """
    Decodes JSON strings to Intel objects
    """

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.decode_hook, *args, **kwargs)

    def decode_hook(self, dct: dict):
        if "intel_type" in dct and "indicator" in dct:
            # parse IntelData
            intel_type = IntelType(int(dct.pop("intel_type")))
            indicator = tuple(dct.pop("indicator"))
            return IntelData(indicator, intel_type, **dct)
        elif "ts" in dct and "id" in dct and "data" in dct and "operation" in dct:
            # parse Intel
            return Intel(
                parser.parse(dct["ts"]),
                dct["id"],
                dct["data"],
                Operation(dct["operation"]),
            )
        return dct


class SightingEncoder(json.JSONEncoder):
    """
    Encodes Sighting objects to JSON strings
    """

    def default(self, sighting: Sighting):
        if type(sighting) is not Sighting:
            # let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, sighting)
        return {
            "ts": str(sighting.ts),
            "intel": sighting.intel,
            "context": sighting.context,
            "ioc": list(sighting.ioc) if sighting.ioc else None,
        }


class SightingDecoder(json.JSONDecoder):
    """
    Decodes JSON strings to Sighting objects
    """

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.decode_hook, *args, **kwargs)

    def decode_hook(self, dct: dict):
        if "ts" in dct and "intel" in dct and "context" in dct:
            ioc = dct.get("ioc", None)
            if ioc:
                ioc = tuple(ioc)
            return Sighting(parser.parse(dct["ts"]), dct["intel"], dct["context"], ioc)
        return dct


class SnapshotRequestEncoder(json.JSONEncoder):
    """
    Encodes SnapshotRequest objects to JSON strings
    """

    def default(self, req: SnapshotRequest):
        if type(req) is not SnapshotRequest:
            # let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, req)
        return {
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
        if "snapshot_type" in dct and "snapshot_id" in dct and "snapshot" in dct:
            return SnapshotRequest(
                MessageType(int(dct["snapshot_type"])),
                dct["snapshot_id"],
                timedelta(seconds=dct["snapshot"]),
            )
        return dct


class SnapshotEnvelopeEncoder(json.JSONEncoder):
    """
    Encodes SnapshotEnvelope objects to JSON strings
    """

    def default(self, env: SnapshotEnvelope):
        if type(env) is not SnapshotEnvelope:
            # let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, env)
        encoder = None
        if type(env.body) is Intel:
            encoder = IntelEncoder
        elif type(env.body) is Sighting:
            encoder = SightingEncoder
        else:
            # let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, env)
        return {
            "snapshot_type": int(env.snapshot_type.value),
            "snapshot_id": str(env.snapshot_id),
            "body": encoder.default(self, env.body),
        }


class SnapshotEnvelopeDecoder(json.JSONDecoder):
    """
    Decodes JSON strings to SnapshotEnvelope objects
    """

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.decode_hook, *args, **kwargs)

    def decode_hook(self, dct: dict):
        if "snapshot_type" in dct and "snapshot_id" in dct and "body" in dct:
            snapshot_type = MessageType(int(dct["snapshot_type"]))
            return SnapshotEnvelope(
                snapshot_type,
                dct["snapshot_id"],
                dct["body"],
            )
        if (
            "intel_type" in dct
            and "indicator" in dct
            or "ts" in dct
            and "id" in dct
            and "data" in dct
            and "operation" in dct
        ):
            return IntelDecoder.decode_hook(self, dct)
        elif "ts" in dct and "intel" in dct and "context" in dct:
            return SightingDecoder.decode_hook(self, dct)
        return dct
