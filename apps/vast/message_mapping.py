from datetime import datetime
from dateutil import parser as dateutil_parser
from ipaddress import ip_address
import json
from threatbus.data import Intel, IntelType, Sighting

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

    if vast_type == "ip":
        return str(indicator)
    if vast_type == "url":
        # TODO: use field annotations, once implemented (ch17531)
        return f'"{indicator}" in url'
    if vast_type == "domain":
        # Currently, uses VAST's suffix-based field matching. Targets every
        # schema with fieldnames that end in `domain`, `host`, or `hostname`
        # (Zeek and Suricata)
        # TODO: use field annotations, once implemented (ch17531)
        return f'"{indicator}" in domain || "{indicator}" in host || "{indicator}" in hostname'
    return None


def query_result_to_threatbus_sighting(query_result: str, intel: Intel):
    """
    Creates a Threat Bus Sighting from a VAST query result.
    @param query_result The query result to convert
    @param intel The intel item that the sighting refers to
    """
    return Sighting(datetime.now(), intel.id, json.loads(query_result))


def matcher_result_to_threatbus_sighting(msg: dict):
    """
    Maps a sighting from the VAST Matcher format to a Threat Bus Sighting.
    @param msg The raw sighting from VAST
    """
    if not isinstance(msg, dict):
        return None
    ts = msg.get("ts", None)
    if type(ts) is str:
        ts = dateutil_parser.parse(ts)
    ref = msg.get("reference", "")
    context = msg.get("context", {})
    if not ts or not ref or not len(ref) > len(threatbus_reference):
        return None
    ref = ref[len(threatbus_reference) :]
    context["source"] = "VAST"
    return Sighting(ts, ref, context)
