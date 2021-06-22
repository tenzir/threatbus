from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
from multiprocessing import JoinableQueue
import pluggy
from typing import List

hookspec = pluggy.HookspecMarker("threatbus.backbone")


@hookspec
def run(config: DynaBox, logging: DynaBox, inq: JoinableQueue):
    """Runs / starts a plugin spec with a configuration object
    @param config A configuration object for the app
    @param logging A configuration object for the logger
    @param inq The queue on which all received data arrives
    """


@hookspec
def stop():
    """Stops all Threads that the plugin has started."""


@hookspec
def subscribe(topic: str, q: JoinableQueue):
    """Subscribes the given queue to the requested topic.
    @param topic Subscribe to this topic (string)
    @param q A queue object to forward all messages for the given topic
    """


@hookspec
def unsubscribe(topic: str, q: JoinableQueue):
    """Unubscribes the given queue from the requested topic
    @param topic Unsubscribe from this topic (string)
    @param q The queue object that was subscribed to the given topic
    """


@hookspec
def config_validators() -> List[Validator]:
    """
    Returns a list of dynaconf.Validators so the main Threat Bus runtime can
    validate the user-specified configuration.
    """
