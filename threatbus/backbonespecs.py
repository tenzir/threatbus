import pluggy

hookspec = pluggy.HookspecMarker("threatbus.backbone")


@hookspec
def run(config, logging):
    """Runs / starts a plugin spec with a configuration object
    :param config a configuration object for the app
    :param logging a configuration object for the logger
    """