import pluggy

hookspec = pluggy.HookspecMarker("threatbus.backbone")


@hookspec
def run(config, logging, inq):
    """Runs / starts a plugin spec with a configuration object
    :param config a configuration object for the app
    :param logging a configuration object for the logger
    :param inq the queue on which all received data arrives
    """


@hookspec
def subscribe(topics, q):
    """Subscribes the given queue to the requested topics
    :param topics subscribe to these topics
    :param q a queue object to forward all messages for the given topics
    """


@hookspec
def unsubscribe(topics, q):
    """Unubscribes the given queue from the requested topics
    :param topics unsubscribe from these topics
    :param q the queue object that was subscribed to the given topics
    """
