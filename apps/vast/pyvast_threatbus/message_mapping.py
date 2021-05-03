from dateutil import parser as dateutil_parser
import json
from stix2 import Indicator, Sighting
from threatbus.data import ThreatBusSTIX2Constants
from threatbus.stix2_helpers import is_point_equality_ioc, split_object_path_and_value
from typing import Tuple, Union

vast_ioc_type_map = {
    "ipv4-addr:value": "ip",
    "ipv6-addr:value": "ipv6",
    "domain-name:value": "domain",
    "url:value": "url",
}

threatbus_reference = "threatbus__"


def vast_escape_str(val: str):
    """
    Strings need to be passed to VAST in double quotes. In consequence, we must
    escape double quotes before querying VAST.
    """

    val = val.replace("\\", "\\\\")
    return val.replace('"', '\\"')


def get_vast_type_and_value(pattern_str: str) -> Union[Tuple[str, str], None]:
    if not is_point_equality_ioc(pattern_str):
        return None
    object_path, ioc_value = split_object_path_and_value(pattern_str)
    ioc_value = vast_escape_str(ioc_value)
    vast_type = vast_ioc_type_map.get(object_path, None)
    if not vast_type:
        return None
    return vast_type, ioc_value


def indicator_to_vast_matcher_ioc(indicator: Indicator) -> Union[str, None]:
    """
    Maps a STIX-2 Indicator to a VAST compatible IoC format (JSON), so that a
    VAST matcher can ingest it.
    @param indicator The item to map
    @return an IoC in JSON format that a VAST matcher can read or None
    """
    if type(indicator) is not Indicator:
        return None

    type_and_value = get_vast_type_and_value(indicator.pattern)
    if not type_and_value:
        return None
    (vast_type, ioc_value) = type_and_value

    return json.dumps(
        {
            "value": ioc_value,
            "type": vast_type,
            "reference": f"{threatbus_reference}{indicator.id}",
        }
    )


def indicator_to_vast_query(indicator: Indicator) -> Union[str, None]:
    """
    Creates a VAST query from a Threat Bus Intel item.
    @param intel The item to map
    @return a valid VAST query string or None
    """
    if type(indicator) is not Indicator:
        return None

    type_and_value = get_vast_type_and_value(indicator.pattern)
    if not type_and_value:
        return None
    (vast_type, ioc_value) = type_and_value

    if vast_type == "ip" or vast_type == "ipv6":
        return ioc_value
    if vast_type == "url":
        return f'"{ioc_value}" in net.uri'
    if vast_type == "domain":
        return f'"{ioc_value}" == net.domain || "{ioc_value}" == net.hostname'
    return None


def query_result_to_sighting(
    query_result: str, indicator: Indicator
) -> Union[Sighting, None]:
    """
    Creates a STIX-2 Sighting from a VAST query result and the STIX-2 indicator
    that the query result refers to.
    @param query_result The VAST query result to convert
    @param indicator The STIX-2 Indicator that the query result refers to
    @return a valid STIX-2 Sighting that references the given indicator or None
    """
    if type(query_result) is not str or type(indicator) is not Indicator:
        return None
    try:
        context = json.loads(query_result)
        context["source"] = "VAST"
        ts = context.get("ts", context.get("timestamp", None))
        if not ts:
            return None
        ts = dateutil_parser.parse(ts)
        return Sighting(
            last_seen=ts,
            sighting_of_ref=indicator.id,
            custom_properties={
                ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value: context,
                ThreatBusSTIX2Constants.X_THREATBUS_INDICATOR.value: indicator,
            },
        )
    except Exception:
        return None


def matcher_result_to_sighting(matcher_result: str) -> Union[Sighting, None]:
    """
    Maps a sighting from the VAST Matcher format to a STIX-2 Sighting.
    @param matcher_result The raw sighting from VAST
    @return a valid STIX-2 Sighting that references the IoC from the VAST
        matcher or None
    """
    if type(matcher_result) is not str:
        return None
    try:
        dct = json.loads(matcher_result)
        ts = dct.get("ts", None)
        if type(ts) is str:
            ts = dateutil_parser.parse(ts)
    except Exception:
        return None
    ref = dct.get("reference", "")
    context = dct.get("context", {})
    ioc_value = dct.get("value", "")
    # ref = threatbus__indicator--46b3f973-5c03-41fc-9efe-49598a267a35
    ref_len = len(threatbus_reference) + len("indicator--") + 36
    if not ts or not ref or not len(ref) == ref_len:
        return None
    ref = ref[len(threatbus_reference) :]
    context["source"] = "VAST"
    return Sighting(
        last_seen=ts,
        sighting_of_ref=ref,
        custom_properties={
            ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value: context,
            ThreatBusSTIX2Constants.X_THREATBUS_INDICATOR_VALUE.value: ioc_value,
        },
    )
