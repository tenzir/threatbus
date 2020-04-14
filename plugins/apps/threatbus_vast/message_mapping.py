from datetime import timedelta
from threatbus.data import Intel, IntelType, Subscription, Unsubscription
import json
import ipaddress

to_vast_intel = {
    IntelType.IPSRC: "ip",
    IntelType.IPDST: "ip",
    IntelType.HOSTNAME: "domain",
    IntelType.DOMAIN: "domain",
    IntelType.DOMAIN_IP: "domain",
    IntelType.URL: "url",
}


def map_management_message(msg):
    """Maps a management message to an actionable instruction for threatbus.
        @param msg The message that was received, as python dictionary
    """
    action = msg.get("action", None)
    topic = msg.get("topic", None)
    snapshot = msg.get("snapshot", 0)
    snapshot = timedelta(days=int(snapshot))
    if action == "subscribe" and topic is not None and snapshot is not None:
        return Subscription(topic, snapshot)
    elif action == "unsubscribe" and topic is not None:
        return Unsubscription(topic)


def map_intel_to_vast(intel: Intel):
    """Maps an Intel item to a VAST compatible format;
        @param intel The item to map
    """
    if not type(intel).__name__.lower() == "intel":
        return None
    vast_type = to_vast_intel.get(intel.data["intel_type"], None)
    if not vast_type:
        return None

    indicator = intel.data["indicator"][0]  # indicators are tuples in Threat Bus
    if vast_type == "ADDR" and ipaddress.ip_address(indicator).version == 6:
        vast_type = "ipv6"

    return json.dumps(
        {
            "ioc": indicator,
            "type": vast_type,
            "reference": f"threatbus__{intel.id}",
            "operation": intel.operation.value,
        }
    )


def map_vast_sighting(msg):
    """Maps a VAST sighting to Threat Bus internal format
        @param msg The raw sighting from VAST (dict)
    """
    # TODO: Implement once the report format for IOC references is known.
    return msg
