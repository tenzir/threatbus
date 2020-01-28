import broker
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta
from threatbus.data import Intel, IntelData, IntelType, Operation, Sighting
import re

# See https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
to_zeek_intel = {
    IntelType.IPSRC: "ADDR",
    IntelType.IPDST: "ADDR",
    IntelType.IPSRC_PORT: "ADDR",
    IntelType.IPDST_PORT: "ADDR",
    IntelType.EMAILSRC: "EMAIL",
    IntelType.EMAILDST: "EMAIL",
    IntelType.TARGETEMAIL: "EMAIL",
    IntelType.EMAILATTACHMENT: "FILE_NAME",
    IntelType.FILENAME: "FILE_NAME",
    IntelType.HOSTNAME: "DOMAIN",
    IntelType.DOMAIN: "DOMAIN",
    IntelType.DOMAIN_IP: "DOMAIN",
    IntelType.URL: "URL",
    IntelType.USERAGENT: "SOFTWARE",
    IntelType.MD5: "FILE_HASH",
    IntelType.MALWARESAMPLE: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_MD5: ("FILE_NAME", "FILE_HASH"),
    IntelType.SHA1: "FILE_HASH",
    IntelType.FILENAME_SHA1: ("FILE_NAME", "FILE_HASH"),
    IntelType.SHA256: "FILE_HASH",
    IntelType.FILENAME_SHA256: ("FILE_NAME", "FILE_HASH"),
    IntelType.X509FINGERPRINTSHA1: "CERT_HASH",
    IntelType.PDB: "FILE_NAME",
    IntelType.AUTHENTIHASH: "FILE_HASH",
    IntelType.SSDEEP: "FILE_HASH",
    IntelType.IMPHASH: "FILE_HASH",
    IntelType.PEHASH: "FILE_HASH",
    IntelType.IMPFUZZY: "FILE_HASH",
    IntelType.SHA224: "FILE_HASH",
    IntelType.SHA384: "FILE_HASH",
    IntelType.SHA512: "FILE_HASH",
    IntelType.SHA512_224: "FILE_HASH",
    IntelType.SHA512_256: "FILE_HASH",
    IntelType.TLSH: "FILE_HASH",
    IntelType.CDHASH: "FILE_HASH",
    IntelType.FILENAME_AUTHENTIHASH: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_SSDEEP: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_IMPHASH: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_PEHASH: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_IMPFUZZY: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_SHA224: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_SHA384: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_SHA512: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_SHA512_224: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_SHA512_256: ("FILE_NAME", "FILE_HASH"),
    IntelType.FILENAME_TLSH: ("FILE_NAME", "FILE_HASH"),
}

from_zeek_intel = {
    "ADDR": IntelType.IPSRC,
    "EMAIL": IntelType.EMAILSRC,
    "FILE_NAME": IntelType.FILENAME,
    "DOMAIN": IntelType.DOMAIN,
    "URL": IntelType.URL,
    "SOFTWARE": IntelType.USERAGENT,
    "FILE_HASH": IntelType.MD5,
}


@dataclass
class Subscription:
    topic: str
    snapshot: timedelta


@dataclass
class Unsubscription:
    topic: str


def map_management_message(broker_data, module_namespace):
    """Maps a management message to an actionable instruction for threatbus.
        @param broker_data The raw data that was received via broker
        @param module_namespace A Zeek namespace to accept events from
    """
    event = broker.zeek.Event(broker_data)
    name, args = event.name(), event.args()
    module_namespace = module_namespace + "::" if module_namespace else ""
    name = name[name.startswith(module_namespace) and len(module_namespace) :]
    if name == "subscribe" and len(args) == 2:
        return Subscription(args[0], args[1])
    elif name == "unsubscribe" and len(args) == 1:
        return Unsubscription(args[0])


def map_broker_intel_to_internal(intel_dict):
    """Maps a intel dict with zeek Intel::Type values to the threatbus.data.IntelData Type
        @param intel_dict The data to map into Threat Bus format
    """
    zeek_type = intel_dict.get("intel_type", None)
    intel_type = from_zeek_intel.get(zeek_type, None)
    indicator = intel_dict.get("indicator", None)
    if not intel_type or not indicator:
        return None

    return IntelData(indicator, intel_type)


def map_to_internal(broker_data, module_namespace):
    """Maps a broker message, based on the event name, to the internal format.
        @param broker_data The raw data that was received via broker
        @param module_namespace A Zeek namespace to accept events from
    """
    event = broker.zeek.Event(broker_data)
    name, args = event.name(), event.args()
    module_namespace = module_namespace + "::" if module_namespace else ""
    name = name[name.startswith(module_namespace) and len(module_namespace) :]
    if name == "sighting" and len(args) == 3:
        # convert args to sighting
        return Sighting(args[0], str(args[1]), args[2])
    elif name == "intel" and len(args) >= 3:
        # convert args to intel
        op = Operation.ADD
        with suppress(Exception):
            op = Operation(args[3])
        intel_data = map_broker_intel_to_internal(args[2])
        if not intel_data:
            return None
        return Intel(args[0], str(args[1]), intel_data, op)


def map_intel_data_to_broker(intel_data):
    """Maps threatbus.data.IntelData to a broker compatible type and zeek compatible Intel::Type values.
        @param intel_data The Threat Bus intel data to map
    """
    zeek_type = to_zeek_intel.get(intel_data["intel_type"], None)
    if not zeek_type:
        return None

    indicator = intel_data["indicator"]
    if isinstance(zeek_type, str):
        indicator = indicator[0]
        if zeek_type == "URL":
            indicator = re.sub(r"^https?://", "", indicator)
        elif zeek_type == "ADDR" and re.match(".+/.+", indicator):
            zeek_type = "SUBNET"  # elevate to subnet if possible
    elif isinstance(zeek_type, tuple):
        if len(zeek_type) != 2 and len(indicator) < 2:
            return None
        # prefer to use file hashes
        if indicator[1]:
            indicator = indicator[1]
            zeek_type = zeek_type[1]
        else:
            indicator = indicator[0]
            zeek_type = zeek_type[0]
    else:
        return None
    return {"indicator": indicator, "intel_type": zeek_type}


def map_to_broker(msg, module_namespace):
    """Maps the internal message format to a broker message.
        @param msg The message that shall be converted
        @param module_namespace A Zeek namespace to use for event sending
        @return The mapped broker event or None
    """
    msg_type = type(msg).__name__.lower()
    if msg_type == "sighting":
        # convert sighting to zeek event
        return broker.zeek.Event(
            f"{module_namespace}::sighting", (msg.ts, str(msg.intel), msg.context),
        )
    elif msg_type == "intel":
        # convert intel to zeek event
        intel_data = map_intel_data_to_broker(msg.data)
        if not intel_data:
            return None
        return broker.zeek.Event(
            f"{module_namespace}::intel",
            (msg.ts, str(msg.id), intel_data, msg.operation.value),
        )
