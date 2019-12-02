import asyncio
import broker
import broker.zeek
import logging
import re

POLL_INTERVAL = 0.05

class Zeek:
    def __init__(self, config):
        self.logger = logging.getLogger("threat-bus.zeek")
        self.config = config
        self.endpoint = broker.Endpoint()
        self.logger.debug(f"created endpoint {self.endpoint.node_id()}")
        self.subscriber = self.endpoint.make_subscriber([config.topic])
        self.logger.debug(f"creating subscriber for topic '{config.topic}'")
        self.logger.info("establishing peering with Zeek at "
                         f"{config.host}:{config.port}")
        self.endpoint.peer(config.host, config.port)
        self.logger.debug("established peering succesfully, sending hello")
        self.put("Tenzir::hello", self.endpoint.node_id())

    def add_intel(self, intel):
        """Forwards intelligence to Zeek"""
        zeek_intel = to_zeek(intel)
        if not zeek_intel:
            self.logger.warning(f"ignoring incompatible intel: {intel}")
            return
        self.logger.debug(f"adding intel to Zeek: {intel}")
        event = broker.zeek.Event("Tenzir::add_intel", zeek_intel)
        self.endpoint.publish(self.config.topic, event)

    def remove_intel(self, intel):
        """Forwards intelligence to Zeek"""
        zeek_intel = to_zeek(intel)
        if not zeek_intel:
            self.logger.warning(f"ignoring incompatible intel: {intel}")
            return
        self.logger.debug(f"deleting intel from Zeek: {intel}")
        event = broker.zeek.Event("Tenzir::remove_intel", zeek_intel)
        self.endpoint.publish(self.config.topic, event)

    def dump_intel(self, source=""):
        """Retrieves an intel snapshot from Zeek"""
        self.logger.debug(f"requesting intel snapshot from Zeek")
        request = broker.zeek.Event("Tenzir::intel_snapshot_request", source)
        self.endpoint.publish(self.config.topic, request)

    async def get(self):
        """Retrieves an event from Zeek via Broker"""
        while True:
            if self.subscriber.available():
                topic, data = self.subscriber.get()
                event = broker.zeek.Event(data)
                self.logger.debug(f"{topic} -> event {event.name()}{event.args()}")
                return event
            else:
                # This is a poor workaround for the lack of asynchrony in the
                # Broker Python bindings. For some weird reason, we cannot just
                # run this function in the executor because it blocks all other
                # coroutines. So now we do polling with asynchronous sleepping
                # at fixed rate.
                await asyncio.sleep(POLL_INTERVAL)

    def put(self, event_name, *args):
        """Sends an event to Zeek via Broker"""
        event = broker.zeek.Event(event_name, *args)
        self.endpoint.publish(self.config.topic, event)

def to_zeek(intel):
    """Translates intel into Zeek intel"""
    def translate(intel_type, intel_value):
        def normalize(t, x):
            if t == "URL":
                # Normalize URLs
                return (t, re.sub(r"^https?://", "", x))
            if t == "ADDR":
                # Elevate ADDR to SUBNET if possible.
                return ("SUBNET", x) if re.match(".+/.+", x) else (t, x)
            return (t, x)
        if intel_type not in to_zeek.mapping:
            return None
        zeek_type = to_zeek.mapping[intel_type]
        if isinstance(zeek_type, str):
            return normalize(zeek_type, intel_value)
        if isinstance(zeek_type, tuple):
            if len(zeek_type) != 2:
                raise AssertionError("composite type must have two elements")
            values = intel_value.split("|")
            if len(values) != 2:
                raise ValueError("expected '|'-separated composite values")
            t0, x0 = normalize(zeek_type[0], values[0])
            t1, x1 = normalize(zeek_type[1], values[1])
            # Sanity check the expected format.
            if t0 == "FILE_HASH":
                raise AssertionError("FILE_HASH does not occur as first type")
            if not (t0 or t1):
                raise AssertionError("at least one type must be defined")
            if not t0:
                return (t1, x1)
            if not t1:
                return (t0, x0)
            # Prefer file hashes over names because they are more robust.
            # (Unlike a file name, the hash remains the same.)
            if t0 == "FILE_HASH":
                return (t0, x0)
            if t1 == "FILE_HASH":
                return (t1, x1)
            # TODO: we may consider returning a list of Zeek intel instead to
            # indicate that a single intel can result in multiple Zeek intel
            # items. For now, if we can still choose between two types, we
            # simply choose the second type.
            return (t1, x1)
        raise AssertionError("zeek type must be 'str' or 'tuple'")
    xs = translate(intel.type, intel.value)
    return [intel.id, *xs, intel.source] if xs else None

# See https://github.com/MISP/MISP/blob/2.4/app/Lib/Export/BroExport.php
# for the baseline.
to_zeek.mapping = {
    "ip-src": "ADDR",
    "ip-dst": "ADDR",
    "ip-src|port": ("ADDR", None),
    "ip-dst|port": ("ADDR", None),
    "email-src": "EMAIL",
    "email-dst": "EMAIL",
    "target-email": "EMAIL",
    "email-attachment": "FILE_NAME",
    "filename": "FILE_NAME",
    "hostname": "DOMAIN",
    "domain": "DOMAIN",
    "domain|ip": ("DOMAIN", "ADDR"),
    "url": "URL",
    "user-agent": "SOFTWARE",
    "md5": "FILE_HASH",
    "malware-sample": ("FILE_NAME", "FILE_HASH"),
    "filename|md5": ("FILE_NAME", "FILE_HASH"),
    "sha1": "FILE_HASH",
    "filename|sha1": ("FILE_NAME", "FILE_HASH"),
    "sha256": "FILE_HASH",
    "filename|sha256": ("FILE_NAME", "FILE_HASH"),
    "x509-fingerprint-sha1": "CERT_HASH",
    "pdb": "FILE_NAME",
    "authentihash": "FILE_HASH",
    "ssdeep": "FILE_HASH",
    "imphash": "FILE_HASH",
    "pehash": "FILE_HASH",
    "impfuzzy": "FILE_HASH",
    "sha224": "FILE_HASH",
    "sha384": "FILE_HASH",
    "sha512": "FILE_HASH",
    "sha512/224": "FILE_HASH",
    "sha512/256": "FILE_HASH",
    "tlsh": "FILE_HASH",
    "cdhash": "FILE_HASH",
    "filename|authentihash": ("FILE_NAME", "FILE_HASH"),
    "filename|ssdeep": ("FILE_NAME", "FILE_HASH"),
    "filename|imphash": ("FILE_NAME", "FILE_HASH"),
    "filename|pehash": ("FILE_NAME", "FILE_HASH"),
    "filename|impfuzzy": ("FILE_NAME", "FILE_HASH"),
    "filename|sha224": ("FILE_NAME", "FILE_HASH"),
    "filename|sha384": ("FILE_NAME", "FILE_HASH"),
    "filename|sha512": ("FILE_NAME", "FILE_HASH"),
    "filename|sha512/224": ("FILE_NAME", "FILE_HASH"),
    "filename|sha512/256": ("FILE_NAME", "FILE_HASH"),
    "filename|tlsh": ("FILE_NAME", "FILE_HASH"),
}