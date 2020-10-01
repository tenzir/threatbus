import threading
from collections import defaultdict
import threatbus

"""In-Memory backbone plugin for Threat Bus"""

plugin_name = "inmem"

subscriptions = defaultdict(set)
lock = threading.Lock()


def validate_config(config):
    return True


def provision(inq):
    """
    Provisions all messages that arrive on the inq to all subscribers of that topic.
    @param inq The in-Queue to read messages from
    """
    global subscriptions, lock, logger
    while True:
        msg = inq.get(block=True)
        logger.debug(f"Backbone got message {msg}")
        topic = f"threatbus/{type(msg).__name__.lower()}"
        lock.acquire()
        for t in filter(lambda t: str(topic).startswith(str(t)), subscriptions.keys()):
            for outq in subscriptions[t]:
                outq.put(msg)
        lock.release()
        inq.task_done()


@threatbus.backbone
def subscribe(topic, q):
    global logger, subscriptions, lock
    logger.info(f"Adding subscription to: {topic}")
    lock.acquire()
    subscriptions[topic].add(q)
    lock.release()


@threatbus.backbone
def unsubscribe(topic, q):
    global logger, subscriptions, lock
    logger.info(f"Removing subscription from: {topic}")
    lock.acquire()
    if q in subscriptions[topic]:
        subscriptions[topic].remove(q)
    lock.release()


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
    logger.info("In-memory backbone started.")
