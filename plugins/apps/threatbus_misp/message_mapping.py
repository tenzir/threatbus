from datetime import datetime
from threatbus.data import Intel, IntelData, IntelType, Operation, Sighting
import pymisp
from typing import Dict, List


misp_intel_type_mapping: Dict[str, IntelType] = {
    "ip-src": IntelType.IPSRC,
    "ip-dst": IntelType.IPDST,
    "ip-src|port": IntelType.IPSRC_PORT,
    "ip-dst|port": IntelType.IPDST_PORT,
    "email-src": IntelType.EMAILSRC,
    "email-dst": IntelType.EMAILDST,
    "target-email": IntelType.TARGETEMAIL,
    "email-attachment": IntelType.EMAILATTACHMENT,
    "filename": IntelType.FILENAME,
    "hostname": IntelType.HOSTNAME,
    "domain": IntelType.DOMAIN,
    "domain|ip": IntelType.DOMAIN_IP,
    "url": IntelType.URL,
    "uri": IntelType.URL,
    "user-agent": IntelType.USERAGENT,
    "md5": IntelType.MD5,
    "malware-sample": IntelType.MALWARESAMPLE,
    "filename|md5": IntelType.FILENAME_MD5,
    "sha1": IntelType.SHA1,
    "filename|sha1": IntelType.FILENAME_SHA1,
    "sha256": IntelType.SHA256,
    "filename|sha256": IntelType.FILENAME_SHA256,
    "x509-fingerprint-sha1": IntelType.X509FINGERPRINTSHA1,
    "pdb": IntelType.PDB,
    "authentihash": IntelType.AUTHENTIHASH,
    "ssdeep": IntelType.SSDEEP,
    "imphash": IntelType.IMPHASH,
    "pehash": IntelType.PEHASH,
    "impfuzzy": IntelType.IMPFUZZY,
    "sha224": IntelType.SHA224,
    "sha384": IntelType.SHA384,
    "sha512": IntelType.SHA512,
    "sha512/224": IntelType.SHA512_224,
    "sha512/256": IntelType.SHA512_256,
    "tlsh": IntelType.TLSH,
    "cdhash": IntelType.CDHASH,
    "filename|authentihash": IntelType.FILENAME_AUTHENTIHASH,
    "filename|ssdeep": IntelType.FILENAME_SSDEEP,
    "filename|imphash": IntelType.FILENAME_IMPHASH,
    "filename|pehash": IntelType.FILENAME_PEHASH,
    "filename|impfuzzy": IntelType.FILENAME_IMPFUZZY,
    "filename|sha224": IntelType.FILENAME_SHA224,
    "filename|sha384": IntelType.FILENAME_SHA384,
    "filename|sha512": IntelType.FILENAME_SHA512,
    "filename|sha512/224": IntelType.FILENAME_SHA512_224,
    "filename|sha512/256": IntelType.FILENAME_SHA512_256,
    "filename|tlsh": IntelType.FILENAME_TLSH,
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


def map_to_internal(misp_attribute: dict, action: str, logger=None):
    """
    Maps the given MISP attribute to the threatbus Intel format. Discards all
    messages that do not match the given filter, if any.
    @param misp_attribute The MISP attribute to map
    @param action A string from MISP, describing the action for the attribute
        (either 'add' or 'delete')
    @return The mapped intel item or None
    """
    # parse MISP attribute
    if not misp_attribute:
        return None
    to_ids = misp_attribute.get("to_ids", False)
    if not to_ids and action != "edit" or not action:
        return None
    operation = Operation.REMOVE
    if (action == "edit" or action == "add") and to_ids:
        operation = Operation.ADD

    # parse values
    intel_type = misp_attribute.get("type", None)
    indicator = misp_attribute.get("value", None)
    if not intel_type or not indicator:
        return None

    # parse compound MISP intel:
    if "|" in intel_type:
        indicator = tuple(indicator.split("|"))
        if len(indicator) != 2:
            if logger:
                logger.debug(
                    f"Expected '|'-separated composite values for MISP intel type {intel_type}"
                )
            return None
    tb_intel_type = misp_intel_type_mapping.get(intel_type, None)
    if not tb_intel_type:
        return None
    return Intel(
        datetime.fromtimestamp(int(misp_attribute["timestamp"])),
        str(misp_attribute["id"]),
        IntelData(
            indicator,
            tb_intel_type,
            source="MISP",
        ),
        operation,
    )


def map_to_misp(sighting: Sighting):
    """
    Maps the threatbus sighting format to a MISP sighting.
    @param sighting A threatbus Sighting object
    @return the mapped MISP sighting object or None
    """
    if not sighting or not type(sighting) == Sighting:
        return None

    misp_sighting = pymisp.MISPSighting()
    misp_sighting.from_dict(
        id=sighting.intel,
        source=sighting.context.get("source", None),
        type="0",  # true positive sighting: https://www.circl.lu/doc/misp/automation/#post-sightingsadd
        timestamp=sighting.ts,
    )
    return misp_sighting
