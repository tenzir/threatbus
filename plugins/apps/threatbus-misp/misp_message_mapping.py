from datetime import datetime
from threatbus.data import Intel, IntelData, IntelType, Operation, Sighting
import pymisp

misp_intel_type_mapping = {
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


def map_to_internal(misp_attribute, action, logger=None):
    """Maps the given MISP attribute to the threatbus intel format.
        @param misp_attribute A MISP attribute
        @param action A string from MISP, describing the action for the attribute (either 'add' or 'delete')
        @return the mapped intel item or None
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

    return Intel(
        datetime.fromtimestamp(int(misp_attribute["timestamp"])),
        str(misp_attribute["id"]),
        IntelData(indicator, misp_intel_type_mapping[intel_type], source="MISP",),
        operation,
    )


def map_to_misp(sighting):
    """Maps the threatbus sighting format to a MISP sighting.
        @param sighting A threatbus Sighting object
        @return the mapped MISP sighting object or None
    """
    if not sighting or not isinstance(sighting, Sighting):
        return None

    misp_sighting = pymisp.MISPSighting()
    misp_sighting.from_dict(
        id=sighting.intel,
        source=sighting.context.get("source", None),
        type="0",  # true positive sighting: https://www.circl.lu/doc/misp/automation/#post-sightingsadd
        timestamp=sighting.ts,
    )
    return misp_sighting
