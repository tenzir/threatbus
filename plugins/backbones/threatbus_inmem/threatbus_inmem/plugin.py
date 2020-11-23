from collections import defaultdict
from confuse import Subview
from multiprocessing import JoinableQueue
from queue import Empty
import threading
import threatbus
from typing import Dict, List, Set

"""In-Memory backbone plugin for Threat Bus"""

plugin_name = "inmem"

subscriptions: Dict[str, Set[JoinableQueue]] = defaultdict(set)
lock = threading.Lock()
workers: List[threatbus.StoppableWorker] = list()


def validate_config(config):
    return True


class Provisioner(threatbus.StoppableWorker):
    """
    Provisions all messages that arrive on the inq to all subscribers of that topic.
    @param inq The in-queue to read messages from
    """

    def __init__(self, inq: JoinableQueue):
        self.inq = inq
        super(Provisioner, self).__init__()

    def run(self):
        global subscriptions, lock, logger
        while self._running():
            try:
                msg = self.inq.get(block=True, timeout=1)
            except Empty:
                continue
            logger.debug(f"Backbone got message {msg}")
            topic = f"threatbus/{type(msg).__name__.lower()}"
            lock.acquire()
            for t in filter(
                lambda t: str(topic).startswith(str(t)), subscriptions.keys()
            ):
                for outq in subscriptions[t]:
                    outq.put(msg)
            lock.release()
            self.inq.task_done()


@threatbus.backbone
def subscribe(topic: str, q: JoinableQueue):
    global logger, subscriptions, lock
    logger.info(f"Adding subscription to: {topic}")
    lock.acquire()
    subscriptions[topic].add(q)
    lock.release()


@threatbus.backbone
def unsubscribe(topic: str, q: JoinableQueue):
    global logger, subscriptions, lock
    logger.info(f"Removing subscription from: {topic}")
    lock.acquire()
    if q in subscriptions[topic]:
        subscriptions[topic].remove(q)
    lock.release()


@threatbus.backbone
def run(config: Subview, logging: Subview, inq: JoinableQueue):
    global logger, workers
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    workers.append(Provisioner(inq))
    for w in workers:
        w.start()
    logger.info("In-memory backbone started.")


@threatbus.backbone
def stop():
    global logger, workers
    for w in workers:
        if not w.is_alive():
            continue
        w.stop()
        w.join()
    logger.info("In-memory backbone stopped")
