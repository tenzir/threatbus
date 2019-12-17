import pluggy

hookspec = pluggy.HookspecMarker("threatbus.app")


@hookspec
def threatbus_receive():
    """Receive a message from this plugin implementation.

    :return: a message dict
    """


@hookspec
def run(config, logging):
    """Runs / starts a plugin spec with a configuration object
    :param config a configuration object for the app
    :param logging a configuration object for the logger
    """
