import threatbus

"""Zeek network monitor - plugin for Threat Bus
"""

plugin_name = "zeek"


def validate_config(config):
    config["host"].get(str)
    config["port"].get(int)
    config["topic"].get(str)


@threatbus.app
def run(config, logging):
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        raise ValueError("Invalid config for plugin {}: {}".format(plugin_name, str(e)))

@threatbus.app(optionalhook=True)
def threatbus_receive():
    return {"msg": "threatbus zeek impl was called"}
