from confuse import Subview
import pluggy
from queue import Queue

hookspec = pluggy.HookspecMarker("threatbus.backbone")


@hookspec
def run(config: Subview, logging: Subview, inq: Queue):
    """Runs / starts a plugin spec with a configuration object
    @param config A configuration object for the app
    @param logging A configuration object for the logger
    @param inq The queue on which all received data arrives
    """


@hookspec
def subscribe(topic: str, q: Queue):
    """Subscribes the given queue to the requested topic.
    @param topic Subscribe to this topic (string)
    @param q A queue object to forward all messages for the given topic
    """


@hookspec
def unsubscribe(topic: str, q: Queue):
    """Unubscribes the given queue from the requested topic
    @param topic Unsubscribe from this topic (string)
    @param q The queue object that was subscribed to the given topic
    """
