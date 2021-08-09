from dataclasses import dataclass
from datetime import timedelta
from threatbus.data import Subscription, Unsubscription


@dataclass
class Heartbeat:
    # the p2p_topic used for point-to-point communication between the host and
    # the subscriber, not a human-readable topic. I.e., the random string that
    # was sent as respons from the Threat Bus host during subscription.
    topic: str


def map_management_message(msg):
    """
    Maps a management message to an actionable instruction for threatbus.
    @param msg The message that was received, as python dictionary
    """
    action = msg.get("action", None)
    topic = msg.get("topic", None)
    snapshot = msg.get("snapshot", 0)
    snapshot = timedelta(days=int(snapshot))
    if action == "heartbeat" and topic:
        return Heartbeat(topic)
    if action == "subscribe" and topic and snapshot is not None:
        return Subscription(topic, snapshot)
    elif action == "unsubscribe" and topic:
        return Unsubscription(topic)
