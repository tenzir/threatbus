import copy
from dataclasses import dataclass
from datetime import datetime, timedelta
from dateutil import parser
from enum import auto, Enum, unique
import json


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

    def __init__(self, indicator, intel_type: IntelType, *args, **kw):
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
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dct: dict):
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
        }


class SightingDecoder(json.JSONDecoder):
    """
    Decodes JSON strings to Sighting objects
    """

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dct: dict):
        if "ts" in dct and "intel" in dct and "context" in dct:
            return Sighting(parser.parse(dct["ts"]), dct["intel"], dct["context"])
        return dct
