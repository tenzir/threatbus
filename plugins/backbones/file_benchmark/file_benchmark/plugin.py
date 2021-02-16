from collections import defaultdict
from confuse import Subview
from multiprocessing import JoinableQueue
from stix2 import parse
import threading
import threatbus
import time
from typing import Dict, List, Set

"""File-benchmark backbone plugin for Threat Bus"""

plugin_name = "file_benchmark"

workers: List[threading.Thread] = list()
subscriptions: Dict[str, Set[JoinableQueue]] = defaultdict(set)


def validate_config(config):
    config["input_file"].as_filename()
    config["repetitions"].get(int)


class FileProvisioner(threading.Thread):
    """
    Provisions all messages from the input_file to all subscribers.
    """

    def __init__(self, input_file: str, reps: int):
        self.file_path = input_file
        self.reps = reps
        # read file-contents in memory:
        self.input = []
        with open(self.file_path) as f:
            for line in f:
                msg = parse(line, allow_custom=True)
                self.input.append(msg)
        super(FileProvisioner, self).__init__()

    def run(self):
        global logger
        wait = 2
        logger.debug(f"waiting {wait} seconds before provisioning...")
        time.sleep(wait)
        for _ in range(self.reps):
            for msg in self.input:
                topic = f"stix2/{type(msg).__name__.lower()}"
                for outq in subscriptions[topic]:
                    outq.put(msg)


@threatbus.backbone
def subscribe(topic: str, q: JoinableQueue):
    global logger, subscriptions
    logger.info(f"Adding subscription to: {topic}")
    subscriptions[topic].add(q)


@threatbus.backbone
def unsubscribe(topic: str, q: JoinableQueue):
    global logger, subscriptions
    logger.info(f"Removing subscription from: {topic}")
    if q in subscriptions[topic]:
        subscriptions[topic].remove(q)


@threatbus.backbone
def run(config: Subview, logging: Subview, inq: JoinableQueue):
    global logger, workers
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    workers.append(
        FileProvisioner(
            config["input_file"].get(str),
            config["repetitions"].get(int),
        )
    )
    for w in workers:
        w.start()
    logger.info("File-benchmark backbone started.")


@threatbus.backbone
def stop():
    global logger, workers
    for w in workers:
        if not w.is_alive():
            continue
        w.join()
    logger.info("File-benchmark backbone stopped")
