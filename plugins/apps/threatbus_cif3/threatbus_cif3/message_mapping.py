from csirtg_indicator import Indicator as CIFIndicator
from csirtg_indicator.exceptions import InvalidIndicator
from stix2 import Indicator
from threatbus.data import ThreatBusSTIX2Constants
from threatbus.stix2_helpers import is_point_equality_ioc, split_object_path_and_value
from typing import List, Union


cif_supported_types = [
    "ipv4-addr:value",
    "ipv6-addr:value",
    "domain-name:value",
    "email-addr:value",
    "url:value",
    "file:hashes.MD5",
    "file:hashes.'SHA-1'",
    "file:hashes.'SHA-256'",
    "file:hashes.SSDEEP",
]


def map_to_cif(
    indicator: Indicator, confidence: int, tags: List[str], tlp: str, group: str, logger
) -> Union[CIFIndicator, None]:
    """
    Maps a STIX-2 Indicator to a CIFv3 compatible indicator format.
    @param indicator The STIX-2 Indicator to map
    @param confidence The confidence to use when building the CIF indicator
    @param tags The tags to use when building the CIF indicator
    @param tlp The tlp to use when building the CIF indicator
    @param group The group to use when building the CIF indicator
    @return the mapped intel item or None
    """
    if not indicator or type(indicator) is not Indicator:
        logger.debug(f"Expected STIX-2 indicator, discarding {indicator}")
        return None
    if ThreatBusSTIX2Constants.X_THREATBUS_UPDATE.value in indicator:
        logger.debug(
            f"CIFv3 only supports adding indicators, not deleting / editing. Discardig {indicator}"
        )
        return None
    if not is_point_equality_ioc(indicator.pattern):
        logger.debug(f"CIFv3 only supports point indicators, discardig {indicator}")
        return None

    object_path, ioc_value = split_object_path_and_value(indicator.pattern)
    if object_path not in cif_supported_types:
        logger.debug(f"Discardig indicator with unsupported object-path {indicator}")
        return None

    # convert lasttime
    lasttime = indicator.created.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    ioc_dict = {
        "indicator": ioc_value,
        "confidence": confidence,
        "tags": tags,
        "tlp": tlp,
        "group": group,
        "lasttime": lasttime,
    }

    try:
        return CIFIndicator(**ioc_dict)
    except InvalidIndicator as e:
        logger.error(f"Invalid CIF indicator {e}")
    except Exception as e:
        logger.error(f"CIF indicator error: {e}")
