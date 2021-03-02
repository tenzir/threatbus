from datetime import datetime
from functools import partial
from threatbus.data import Operation, Update
import pymisp
from stix2 import (
    AndObservationExpression,
    AutonomousSystem,
    DomainName,
    EmailAddress,
    EqualityComparisonExpression,
    Indicator,
    IPv4Address,
    MACAddress,
    ObjectPath,
    ObservationExpression,
    Sighting,
    URL,
    X509Certificate,
)
from typing import Callable, Dict, List, Union


def observable_value_to_expr(stix2_type, value: str) -> EqualityComparisonExpression:
    """
    Most STIX-2 observables have a 'value' property. This function takes a
    STIX-2 observable type (e.g., DomainName) that uses a value property and
    invokes it's constructor for the given value. Returns a STIX-2
    EqualityComparisonExpression.
    """
    stix_obj = stix2_type(value=value)
    return EqualityComparisonExpression(
        ObjectPath(stix_obj.type, ["value"]), stix_obj.value
    )


def observable_AS_to_expr(number: str) -> EqualityComparisonExpression:
    """
    Autonomous Systems (AS) in STIX-2 have a 'number' property (as opposed to a
    'value'). This function returns a STIX-2 EqualityComparisonExpression for
    an AS number.
    """
    stix_obj = AutonomousSystem(number=int(number))
    return EqualityComparisonExpression(
        ObjectPath(stix_obj.type, ["number"]), stix_obj.number
    )


def observable_x509_to_expr(
    stix2_type, hash_type: str, hash_str: str
) -> EqualityComparisonExpression:
    """
    x509 certificates in STIX-2 have no 'value' property, but an optional field
    'hashes'. This function creates a valid STIX-2 X509Certificate and wraps it
    in an EqualityComparisonExpression.
    """
    hashes = {hash_type: hash_str}  # e.g., {"SHA-256": "aec078..." }
    cert = X509Certificate(hashes=hashes)  # throws an error for invalid hashes
    hash_type = list(cert.hashes.keys())[0]  # STIX-2 corrects case and spelling
    return EqualityComparisonExpression(
        ObjectPath(cert.type, ["hashes", hash_type]), cert.hashes[hash_type]
    )


# Map MISP attribute types [1] [2] to STIX-2 cyber observable objects [3]
# [1]: https://www.misp-standard.org/rfc/misp-standard-core.html#type
# [2]: https://www.circl.lu/doc/misp/categories-and-types/#types
# [3]: https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr

attribute_type_map: Dict[
    str, Union[Callable[[str], Union[EqualityComparisonExpression, str]], None]
] = {
    # TODO: limited to MISP's `network activity` observables for now.
    # Discuss & expand this if needed
    "ip": partial(
        observable_value_to_expr, IPv4Address
    ),  # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html?highlight=IPv4Address#stix2.v21.IPv4Address
    "ip-src": partial(
        observable_value_to_expr, IPv4Address
    ),  # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html?highlight=IPv4Address#stix2.v21.IPv4Address
    "ip-dst": partial(
        observable_value_to_expr, IPv4Address
    ),  # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html?highlight=IPv4Address#stix2.v21.IPv4Address
    # "ip-dst|port" -> compound types are mapped via their individual parts
    # "ip-src|port" -> compound types are mapped via their individual parts
    "port": None,  # TODO no appropriate mapping to a STIX-2 observable
    "hostname": partial(
        observable_value_to_expr, DomainName
    ),  # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html#stix2.v21.DomainName
    "domain": partial(
        observable_value_to_expr, DomainName
    ),  # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html#stix2.v21.DomainName
    # "domain|ip" -> compound types are mapped via their individual parts
    "mac-address": partial(
        observable_value_to_expr, MACAddress
    ),  # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html#stix2.v21.MACAddress
    "mac-eui-64": partial(
        observable_value_to_expr, MACAddress
    ),  # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html#stix2.v21.MACAddress
    "email": partial(
        observable_value_to_expr, EmailAddress
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_wmenahkvqmgj
    "email-dst": partial(
        observable_value_to_expr, EmailAddress
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_wmenahkvqmgj
    "email-src": partial(
        observable_value_to_expr, EmailAddress
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_wmenahkvqmgj
    "eppn": partial(
        observable_value_to_expr, EmailAddress
    ),  # EduPersonPricincipalName, looks like an Email. https://github.com/MISP/MISP/issues/5448 https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_wmenahkvqmgj
    "url": partial(
        observable_value_to_expr, URL
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_ah3hict2dez0
    "uri": partial(
        observable_value_to_expr, URL
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_ah3hict2dez0
    "user-agent": None,  # no appropriate mapping to a STIX-2 observable
    "http-method": None,  # no appropriate mapping to a STIX-2 observable
    "AS": observable_AS_to_expr,  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_27gux0aol9e3
    "snort": None,  # no appropriate mapping to a STIX-2 observable
    "pattern-in-file": None,  # no appropriate mapping to a STIX-2 observable
    "filename-pattern": None,  # no appropriate mapping to a STIX-2 observable
    "stix2-pattern": lambda val: val[1:-1]
    if val.startswith("[") and val.endswith("]")
    else val,  # remove brackets, if any
    "pattern-in-traffic": None,  # no appropriate mapping to a STIX-2 observable
    "attachment": None,  # no appropriate mapping to a STIX-2 observable
    "comment": None,  # no appropriate mapping to a STIX-2 observable
    "text": None,  # no appropriate mapping to a STIX-2 observable
    "x509-fingerprint-md5": partial(
        observable_x509_to_expr, X509Certificate, "md5"
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_8abcy1o5x9w1
    "x509-fingerprint-sha1": partial(
        observable_x509_to_expr, X509Certificate, "sha1"
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_8abcy1o5x9w1
    "x509-fingerprint-sha256": partial(
        observable_x509_to_expr, X509Certificate, "sha256"
    ),  # https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_8abcy1o5x9w1
    "ja3-fingerprint-md5": None,  # no appropriate mapping to a STIX-2 observable
    "jarm-fingerprint": None,  # no appropriate mapping to a STIX-2 observable
    "hassh-md5": None,  # no appropriate mapping to a STIX-2 observable
    "hasshserver-md5": None,  # no appropriate mapping to a STIX-2 observable
    "other": None,  # no appropriate mapping to a STIX-2 observable
    "hex": None,  # no appropriate mapping to a STIX-2 observable
    "cookie": None,  # no appropriate mapping to a STIX-2 observable
    # "hostname|port" -> compound types are mapped via their individual parts
    "bro": None,  # no appropriate mapping to a STIX-2 observable
    "zeek": None,  # no appropriate mapping to a STIX-2 observable
    # "anonymised" -> compound types are mapped via their individual parts
    "community-id": None,  # no appropriate mapping to a STIX-2 observable
    "email-subject": None,  # no appropriate mapping to a STIX-2 observable
    "favicon-mmh3": None,  # no appropriate mapping to a STIX-2 observable
}


def get_tags(misp_attr: dict):
    """
    Tags are attached as list of objects to MISP attributes. Returns a list of
    all tag names.
    @param The MISP attribute to get the tag names from
    @return A list of tag names
    """
    return [
        t.get("name", None)
        for t in misp_attr.get("Tag", [])
        if t and t.get("name", None)
    ]


def is_whitelisted(misp_msg: dict, filter_config: List[Dict]):
    """
    Compares the given MISP message against every filter in the filter_config
    list. Returns True if the filter_config is empty or if the event is
    whitelisted according to at least one filter from the filter_config.
    @param misp_msg The MISP message to check
    @param filter_config A list of whitelist-filters for "orgs", "tags", and
        "types"
    @return Boolean flag to indicate if the event is whitelisted
    """
    if not misp_msg:
        return False
    event = misp_msg.get("Event", None)
    attr = misp_msg.get("Attribute", None)
    if not event or not attr:
        return False
    org_id = event.get("org_id", None)
    intel_type = attr.get("type", None)
    tags = get_tags(attr)
    if not org_id or not intel_type:
        return False
    if not filter_config:
        # no whitelist = allow all
        return True
    for fil in filter_config:
        if (
            (not fil.get("orgs", None) or org_id in fil["orgs"])
            and (not fil.get("types", None) or intel_type in fil["types"])
            and (
                not fil.get("tags", None)
                or len(set(tags).intersection(set(fil["tags"]))) > 0
            )
        ):
            return True
    return False


def stix2_indicator_id(attr_uuid: str) -> str:
    """
    Converts any given MISP attribute UUID to a STIX-2 indicator ID.
    @param attr_id The MISP attribute ID to convert
    @return a valid STIX-2 Indicator ID
    """
    return f"indicator--{attr_uuid}"


def misp_id(stix2_indicator_uuid: str) -> str:
    """
    Converts any given STIX-2 indicator ID to a valid UUID.
    @param stix2_indicator_uuid The STIX-2 Indicator ID to convert
    @return a valid uuid
    """
    return stix2_indicator_uuid[len("indicator--") :]


def attribute_to_stix2_indicator(
    misp_attribute: dict, action: str, logger
) -> Union[None, Update, Indicator]:
    """
    Maps the given MISP attribute to a STIX-2 cyber observable object.
    @param misp_attribute The MISP attribute to map to STIX-2
    @param action A string from MISP, describing the action for the attribute
        (either 'add', 'edit', or 'delete')
    @param logger The logger instance from the calling function
    @return The mapped STIX-2 Indicator, a Threat Bus Update, or None
    """
    # parse MISP attribute
    if not misp_attribute:
        return None
    to_ids = misp_attribute.get("to_ids", False)
    if not to_ids and action != "edit" or not action:
        return None
    stix2_id = stix2_indicator_id(misp_attribute["uuid"])
    stix2_timestamp = datetime.fromtimestamp(int(misp_attribute["timestamp"]))
    if action == "edit" and not to_ids:
        return Update(id=stix2_id, operation=Operation.REMOVE)

    ## parse MISP values
    attr_type = misp_attribute.get("type", None)
    attr_value = misp_attribute.get("value", None)
    if not attr_type or not attr_value:
        logger.debug(
            f"Incomplete MISP attribute, missing `type` and/or `value` fields: '{misp_attribute}'"
        )
        return None

    ## parse compound MISP intel:
    if "|" in attr_type:
        obs_exprs = []  # list to hold all ObservationExpressions
        value_splits = attr_value.split("|")
        for idx, attr_type_split in enumerate(attr_type.split("|")):
            stix2_create_func = attribute_type_map.get(attr_type_split, None)
            if not stix2_create_func:
                logger.debug(
                    f"Cannot find matching STIX-2 type for MISP attribute type '{attr_type}'"
                )
                return None
            try:
                eq_expr = stix2_create_func(
                    value_splits[idx]
                )  # EqualitiComparisonExpression
                obs_expr = ObservationExpression(eq_expr)
                obs_exprs.append(obs_expr)
            except Exception as e:
                logger.error(f"Error creating STIX-2 expression: {e}")
        try:
            return Indicator(
                id=stix2_id,
                pattern_type="stix",
                pattern=AndObservationExpression(obs_exprs),
                created=stix2_timestamp,
            )
        except Exception as e:
            logger.error(f"Error creating STIX-2 indicator: {e}")
            return None

    ## parse point-IoC
    stix2_create_func = attribute_type_map.get(attr_type, None)
    if not stix2_create_func:
        logger.debug(
            f"Cannot find matching STIX-2 type for MISP attribute type '{attr_type}'"
        )
        return None
    try:
        expr = stix2_create_func(attr_value)
        return Indicator(
            id=stix2_id,
            pattern_type="stix",
            pattern=ObservationExpression(expr),
            created=stix2_timestamp,
        )
    except Exception as e:
        logger.error(f"Error creating STIX-2 indicator: {e}")
        return None


def stix2_sighting_to_misp(sighting: Sighting):
    """
    Maps the STIX-2 sighting format to a MISP sighting.
    @param sighting A STIX-2 Sighting object
    @return the mapped MISP sighting object or None
    """
    if not sighting or type(sighting) != Sighting:
        return None

    misp_sighting = pymisp.MISPSighting()
    source = None
    if "x_threatbus_source" in sighting.object_properties():
        source = str(sighting.x_threatbus_source)
    misp_sighting.from_dict(
        id=misp_id(sighting.sighting_of_ref),
        source=source,
        type="0",  # true positive sighting: https://www.misp-standard.org/rfc/misp-standard-core.html#sighting
        timestamp=sighting.created,
    )
    return misp_sighting
