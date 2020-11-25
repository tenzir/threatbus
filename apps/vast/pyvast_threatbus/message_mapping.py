from dateutil import parser as dateutil_parser
from ipaddress import ip_address
import json
from threatbus.data import Intel, IntelType, Sighting
from unflatten import unflatten as apply_unflatten

to_vast_intel = {
    IntelType.IPSRC: "ip",
    IntelType.IPDST: "ip",
    IntelType.HOSTNAME: "domain",
    IntelType.DOMAIN: "domain",
    IntelType.DOMAIN_IP: "domain",
    IntelType.URL: "url",
    IntelType.URI: "url",
}

threatbus_reference = "threatbus__"


def get_vast_intel_type(intel: Intel):
    """
    Returns the VAST compatible intel type for the given Threat Bus Intel.
    @param intel The Threat Bus Intel to extract the intel_type from
    """
    if not type(intel) == Intel:
        return None
    return to_vast_intel.get(intel.data["intel_type"], None)


def get_ioc(intel: Intel):
    """
    Extracts the IoC from the given Threat Bus Intel and returns it as plain
    string.
    @param intel The Threat Bus Intel to extract the IoC from
    """
    if not type(intel) == Intel:
        return None
    return intel.data["indicator"][0]  # indicators are tuples in Threat Bus


def to_vast_ioc(intel: Intel):
    """
    Maps a Threat Bus Intel item to a VAST compatible IoC format (JSON)
    @param intel The item to map
    """
    if not type(intel) == Intel:
        return None
    vast_type = get_vast_intel_type(intel)
    if not vast_type:
        return None

    indicator = get_ioc(intel)
    if vast_type == "ip" and ip_address(indicator).version == 6:
        vast_type = "ipv6"

    return json.dumps(
        {
            "ioc": indicator,
            "type": vast_type,
            "reference": f"{threatbus_reference}{intel.id}",
        }
    )


def vast_escape_str(val: str):
    """
    Strings need to be passed to VAST in double quotes. In consequence, we must
    escape double quotes before querying VAST.
    """

    val = val.replace("\\", "\\\\")
    return val.replace('"', '\\"')


def to_vast_query(intel: Intel):
    """
    Creates a VAST query from a Threat Bus Intel item.
    @param intel The item to map
    """
    if not type(intel) == Intel:
        return None
    vast_type = get_vast_intel_type(intel)
    if not vast_type:
        return None
    indicator = get_ioc(intel)
    if not indicator:
        return None
    indicator = vast_escape_str(str(indicator))

    if vast_type == "ip":
        return indicator
    if vast_type == "url":
        return f'"{indicator}" in net.uri'
    if vast_type == "domain":
        return f'"{indicator}" in net.domain || "{indicator}" in net.hostname'
    return None


def query_result_to_threatbus_sighting(
    query_result: str, intel: Intel, unflatten: bool = False
):
    """
    Creates a Threat Bus Sighting from a VAST query result.
    @param query_result The query result to convert
    @param intel The intel item that the sighting refers to
    @param unflatten Boolean flag to unflatten the query_result JSON
    """
    if type(query_result) is not str or type(intel) is not Intel:
        return None
    try:
        context = json.loads(query_result)
        context["source"] = "VAST"
        ts = context.get("ts", context.get("timestamp", None))
        if not ts:
            return None

        return Sighting(
            dateutil_parser.parse(ts),
            intel.id,
            apply_unflatten(context) if unflatten else context,
            intel.data["indicator"],
        )
    except Exception:
        return None


def matcher_result_to_threatbus_sighting(msg: str):
    """
    Maps a sighting from the VAST Matcher format to a Threat Bus Sighting.
    @param msg The raw sighting from VAST
    """
    if type(msg) is not str:
        return None
    try:
        dct = json.loads(msg)
        ts = dct.get("ts", None)
        if type(ts) is str:
            ts = dateutil_parser.parse(ts)
    except Exception:
        return None
    ref = dct.get("reference", "")
    ioc = (dct.get("ioc", ""),)  # ioc's are tuples
    context = dct.get("context", {})
    if (
        not ts
        or not ref
        or not len(ref) > len(threatbus_reference)
        or not ioc
        or not ioc[0]
    ):
        return None
    ref = ref[len(threatbus_reference) :]
    context["source"] = "VAST"
    return Sighting(ts, ref, context, ioc)
