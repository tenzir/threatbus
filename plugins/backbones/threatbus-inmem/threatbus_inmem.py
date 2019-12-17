import threatbus

"""In-Memory backbone plugin for Threat Bus
"""

plugin_name = "inmem"


def validate_config(config):
    return True


@threatbus.backbone
def run(config, logging):
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        raise ValueError("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    logger.info("hi")
