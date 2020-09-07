import threading
from collections import defaultdict
import threatbus

"""RabbitMQ backbone plugin for Threat Bus"""

plugin_name = "rabbitmq"

subscriptions = defaultdict(set)
lock = threading.Lock()


def validate_config(config):
    return True


def provision(inq):
    """
    Provisions all messages that arrive on the inq to all subscribers of that topic.
    @param inq The in-Queue to read messages from
    """
    pass


@threatbus.backbone
def provision_p2p(src_q, dst_q):
    pass


@threatbus.backbone
def subscribe(topic, q):
    pass


@threatbus.backbone
def unsubscribe(topic, q):
    pass


@threatbus.backbone
def run(config, logging, inq):
    global logger
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    threading.Thread(target=provision, args=(inq,), daemon=True).start()
    logger.info("RabbitMQ backbone started.")
