import broker
import re
from stix2 import Indicator, Sighting
from threatbus.data import (
    Operation,
    Subscription,
    ThreatBusSTIX2Constants,
    Unsubscription,
)
from threatbus.stix2_helpers import is_point_equality_ioc, split_object_path_and_value
from typing import Union
from urllib.parse import urlparse

# See the documentation for the Zeek INTEL framework [1] and STIX-2 cyber
# observable objects [2]
# [1] https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
# [2] https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr
zeek_intel_type_map = {
    "domain-name:value": "DOMAIN",
    "email-addr:value": "EMAIL",
    "file:name": "FILE_NAME",
    "file:hashes.MD5": "FILE_HASH",
    "file:hashes.'SHA-1'": "FILE_HASH",
    "file:hashes.'SHA-256'": "FILE_HASH",
    "file:hashes.'SHA-512'": "FILE_HASH",
    "file:hashes.'SHA3-256'": "FILE_HASH",
    "file:hashes.'SHA3-512'": "FILE_HASH",
    "file:hashes.SSDEEP": "FILE_HASH",
    "file:hashes.TLSH": "FILE_HASH",
    "ipv4-addr:value": "ADDR",
    "ipv6-addr:value": "ADDR",
    "software:name": "SOFTWARE",
    "url:value": "URL",
    "user:user_id": "USER_NAME",
    "user:account_login": "USER_NAME",
    "x509-certificate:hashes.'SHA-1'": "CERT_HASH",  # Zeek only supports SHA-1
}


def map_management_message(
    broker_data, module_namespace: str, logger
) -> Union[Subscription, Unsubscription, None]:
    """
    Maps a management message to an actionable instruction for Threat Bus.
    @param broker_data The raw data that was received via broker
    @param module_namespace A Zeek namespace to accept events from
    @return A Subscription/Unsubscription object or None in case there is no
    valid mapping.
    """
    event = broker.zeek.Event(broker_data)
    name, args = event.name(), event.args()
    module_namespace = module_namespace + "::" if module_namespace else ""
    name = name[name.startswith(module_namespace) and len(module_namespace) :]
    if name == "subscribe" and len(args) == 2:
        (topic, snapshot_delta) = args
        if topic:
            return Subscription(topic, snapshot_delta)
    elif name == "unsubscribe" and len(args) == 1:
        topic = args[0]
        if topic:
            return Unsubscription(topic)
    logger.debug(f"Discarding Broker management message with unknown type: {name}")
    return None


def map_broker_event_to_sighting(broker_data, module_namespace, logger):
    """
    Maps a Broker message, based on the event name, to a STIX-2 indicator or
    STIX-2 Sighting.
    @param broker_data The raw data that was received via broker
    @param module_namespace A Zeek namespace to accept events from
    """
    event = broker.zeek.Event(broker_data)
    name, args = event.name(), event.args()
    module_namespace = module_namespace + "::" if module_namespace else ""
    name = name[name.startswith(module_namespace) and len(module_namespace) :]
    if name != "sighting" or len(args) != 3:
        if logger:
            logger.debug(f"Discarding Broker event with unknown type: {name}")
        return None
    # convert args to STIX-2 sighting
    (timestamp, ioc_id, context) = args
    return Sighting(
        sighting_of_ref=str(ioc_id),
        last_seen=timestamp,
        custom_properties={
            ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value: context
        },
    )


def map_indicator_to_broker_event(
    indicator: Indicator, module_namespace: str, logger
) -> Union[broker.zeek.Event, None]:
    """
    Maps STIX-2 Indicators to Broker events using the Zeek Intel format
    @see https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
    @param indicator The STIX-2 Indicator to convert
    @param module_namespace A Zeek namespace to use for sending the event
    @return The mapped broker event or None
    """
    if type(indicator) is not Indicator:
        logger.debug(f"Discarding message, expected STIX-2 Indicator: {indicator}")
        return None

    if not is_point_equality_ioc(indicator.pattern):
        logger.debug(
            f"Zeek only supports point-IoCs. Cannot map compound pattern to a Zeek Intel item: {indicator.pattern}"
        )
        return None
    object_path, ioc_value = split_object_path_and_value(indicator.pattern)

    # get matching Zeek intel type
    zeek_type = zeek_intel_type_map.get(object_path, None)
    if not zeek_type:
        logger.debug(
            f"No matching Zeek type found for STIX-2 indicator type '{object_path}'"
        )
        return None

    if zeek_type == "URL":
        # remove leading protocol, if any
        parsed = urlparse(ioc_value)
        scheme = f"{parsed.scheme}://"
        ioc_value = parsed.geturl().replace(scheme, "", 1)
    elif zeek_type == "ADDR" and re.match(".+/.+", ioc_value):
        # elevate to subnet if possible
        zeek_type = "SUBNET"

    operation = "ADD"  ## Zeek operation to add a new Intel item
    if (
        ThreatBusSTIX2Constants.X_THREATBUS_UPDATE.value in indicator
        and indicator.x_threatbus_update == Operation.REMOVE.value
    ):
        operation = "REMOVE"
    return broker.zeek.Event(
        f"{module_namespace}::intel",
        (indicator.created, str(indicator.id), zeek_type, ioc_value, operation),
    )
