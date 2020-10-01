from datetime import timedelta
from threatbus.data import Subscription, Unsubscription


def map_management_message(msg):
    """
    Maps a management message to an actionable instruction for threatbus.
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
