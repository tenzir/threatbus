from threatbus.data import Intel, IntelType, Operation
from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator

cif_supported_types = [
    IntelType.IPSRC,
    IntelType.IPDST,
    IntelType.EMAILSRC,
    IntelType.HOSTNAME,
    IntelType.DOMAIN,
    IntelType.URL,
    IntelType.MD5,
    IntelType.SHA1,
    IntelType.SHA256,
    IntelType.AUTHENTIHASH,
    IntelType.SSDEEP,
    IntelType.IMPHASH,
    IntelType.PEHASH,
]


def map_to_cif(intel: Intel, logger=None, config=None):
    """Maps an Intel item to a CIFv3 compatible indicator format.
        @param intel The item to map
        @return the mapped intel item or None
    """
    if (
        not intel
        or not config
        or intel.operation != Operation.ADD
        or intel.data["intel_type"] not in cif_supported_types
    ):
        return None

    # parse values
    indicator = intel.data["indicator"][0]  # indicators are tuples in Threatbus
    if not indicator:
        return None

    confidence = config["confidence"].as_number()
    if not confidence:
        confidence = 5

    tags = config["tags"].get(list)
    tlp = config["tlp"].get(str)
    group = config["group"].get(str)

    # convert lasttime
    lasttime = intel.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    ii = {
        "indicator": indicator,
        "confidence": confidence,
        "tags": tags,
        "tlp": tlp,
        "group": group,
        "lasttime": lasttime,
    }

    try:
        ii = Indicator(**ii)
    except InvalidIndicator as e:
        self.error(f"Invalid CIF indicator {e}")
    except Exception as e:
        self.error(f"CIF indicator error: {e}")

    return ii
