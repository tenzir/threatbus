from dataclasses import dataclass
from datetime import datetime
from enum import Enum, unique


@unique
class Operation(Enum):
    ADD = "ADD"
    EDIT = "EDIT"
    REMOVE = "REMOVE"


@unique
class IntelType(Enum):
    IPSRC = "ip-src"
    IPDST = "ip-dst"
    IPSRC_PORT = "ip-src|port"
    IPDST_PORT = "ip-dst|port"
    EMAILSRC = "email-src"
    EMAILDST = "email-dst"
    TARGETEMAIL = "target-email"
    EMAILATTACHMENT = "email-attachment"
    FILENAME = "filename"
    HOSTNAME = "hostname"
    DOMAIN = "domain"
    DOMAIN_IP = "domain|ip"
    URL = "url"
    USERAGENT = "user-agent"
    MD5 = "md5"
    MALWARESAMPLE = "malware-sample"
    FILENAME_MD5 = "filename|md5"
    SHA1 = "sha1"
    FILENAME_SHA1 = "filename|sha1"
    SHA256 = "sha256"
    FILENAME_SHA256 = "filename|sha256"
    X509FINGERPRINTSHA1 = "x509-fingerprint-sha1"
    PDB = "pdb"
    AUTHENTIHASH = "authentihash"
    SSDEEP = "ssdeep"
    IMPHASH = "imphash"
    PEHASH = "pehash"
    IMPFUZZY = "impfuzzy"
    SHA224 = "sha224"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA512_224 = "sha512/224"
    SHA512_256 = "sha512/256"
    TLSH = "tlsh"
    CDHASH = "cdhash"
    FILENAME_AUTHENTIHASH = "filename|authentihash"
    FILENAME_SSDEEP = "filename|ssdeep"
    FILENAME_IMPHASH = "filename|imphash"
    FILENAME_PEHASH = "filename|pehash"
    FILENAME_IMPFUZZY = "filename|impfuzzy"
    FILENAME_SHA224 = "filename|sha224"
    FILENAME_SHA384 = "filename|sha384"
    FILENAME_SHA512 = "filename|sha512"
    FILENAME_SHA512_224 = "filename|sha512/224"
    FILENAME_SHA512_256 = "filename|sha512/256"
    FILENAME_TLSH = "filename|tlsh"


class IntelData(dict):
    def __init__(self, indicator, intel_type: IntelType, *args, **kw):
        super(IntelData, self).__init__(*args, **kw)
        assert indicator, "Intel indicator must be set"
        assert intel_type, "Intel type must be set"
        self["indicator"] = indicator
        self["intel_type"] = intel_type


@dataclass()
class Intel:
    ts: datetime
    id: str
    data: IntelData
    operation: Operation


@dataclass()
class Sighting:
    ts: datetime
    intel: str
    context: dict
