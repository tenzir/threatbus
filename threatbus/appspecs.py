import pluggy

hookspec = pluggy.HookspecMarker("threatbus.app")


@hookspec
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
    """Runs / starts a plugin spec with a configuration object
    :param config a configuration object for the app
    :param logging a configuration object for the logger
    :param inq a queue in which this plugin puts incoming messages
    :param subscribe_callback callback to use by a plugin to notify about new subscriptions
    :param unsubscribe_callback callback to use by a plugin to notify about subscription revocation
    """
