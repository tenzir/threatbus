from collections import defaultdict
from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
from multiprocessing import JoinableQueue
from queue import Empty
import threading
import threatbus
from typing import Dict, List, Set
from stix2 import Sighting, Indicator

"""In-Memory backbone plugin for Threat Bus"""

plugin_name = "inmem"

subscriptions: Dict[str, Set[JoinableQueue]] = defaultdict(set)
lock = threading.Lock()
workers: List[threatbus.StoppableWorker] = list()


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
            topic_prefix = "threatbus"
            if type(msg) is Indicator or type(msg) is Sighting:
                topic_prefix = "stix2"
            topic = f"{topic_prefix}/{type(msg).__name__.lower()}"
            lock.acquire()
            for t in filter(
                lambda t: str(topic).startswith(str(t)), subscriptions.keys()
            ):
                for outq in subscriptions[t]:
                    outq.put(msg)
            lock.release()
            self.inq.task_done()


@threatbus.backbone
def config_validators() -> List[Validator]:
    return []


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
def run(config: DynaBox, logging: DynaBox, inq: JoinableQueue):
    global logger, workers
    assert plugin_name in config, f"Cannot find configuration for {plugin_name} plugin"
    logger = threatbus.logger.setup(logging, __name__)
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
