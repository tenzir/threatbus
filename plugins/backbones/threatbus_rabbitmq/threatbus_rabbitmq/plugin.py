from collections import defaultdict
from confuse import Subview
import pika
from multiprocessing import JoinableQueue
from retry import retry
import threading
import threatbus
from threatbus.data import (
    Intel,
    Sighting,
    SnapshotRequest,
    SnapshotEnvelope,
)
from threatbus_rabbitmq import RabbitMQConsumer, RabbitMQPublisher
from typing import Dict, List, Union


"""RabbitMQ backbone plugin for Threat Bus"""

plugin_name = "rabbitmq"

subscriptions: Dict[str, set] = defaultdict(set)
lock = threading.Lock()
workers: List[threatbus.StoppableWorker] = list()


def validate_config(config: Subview):
    assert config, "config must not be None"
    config["host"].get(str)
    config["port"].get(int)
    config["username"].get(str)
    config["password"].get(str)
    config["vhost"].get(str)
    config["naming_join_pattern"].get(str)
    config["queue"].get(dict)
    config["queue"]["name_suffix"].add("")  # optional
    config["queue"]["name_suffix"].get(str)
    config["queue"]["durable"].get(bool)
    config["queue"]["auto_delete"].get(bool)
    config["queue"]["lazy"].get(bool)
    config["queue"]["exclusive"].get(bool)
    config["queue"]["max_items"].add(0)  # optional
    config["queue"]["max_items"].get(int)


def provision(
    topic: str, msg: Union[Intel, Sighting, SnapshotEnvelope, SnapshotRequest]
):
    """
    Provisions the given `msg` to all subscribers of `topic`.
    @param topic The topic string to use for provisioning
    @param msg The message to provision
    """
    global subscriptions, lock, logger
    lock.acquire()
    for t in filter(lambda t: str(topic).startswith(str(t)), subscriptions.keys()):
        for outq in subscriptions[t]:
            outq.put(msg)
    lock.release()
    logger.debug(f"Relayed message from RabbitMQ: {msg}")


@retry(delay=5)
@threatbus.backbone
def subscribe(topic: str, q: JoinableQueue):
    """
    Threat Bus' subscribe hook. Used to register new app-queues for certain
    topics.
    """
    global logger, subscriptions, lock
    logger.info(f"Adding subscription to: {topic}")
    lock.acquire()
    subscriptions[topic].add(q)
    lock.release()


@threatbus.backbone
def unsubscribe(topic: str, q: JoinableQueue):
    """
    Threat Bus' unsubscribe hook. Used to deregister app-queues from certain
    topics.
    """
    global logger, subscriptions, lock
    logger.info(f"Removing subscription from: {topic}")
    lock.acquire()
    if q in subscriptions[topic]:
        subscriptions[topic].remove(q)
    lock.release()


@threatbus.backbone
def run(config: Subview, logging: Subview, inq: JoinableQueue):
    global subscriptions, lock, logger, workers
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    host = config["host"].get(str)
    port = config["port"].get(int)
    username = config["username"].get(str)
    password = config["password"].get(str)
    vhost = config["vhost"].get(str)
    credentials = pika.PlainCredentials(username, password)
    conn_params = pika.ConnectionParameters(host, port, vhost, credentials)
    name_pattern = config["naming_join_pattern"].get(str)
    workers.append(
        RabbitMQConsumer(conn_params, name_pattern, config["queue"], provision, logger)
    )
    workers.append(RabbitMQPublisher(conn_params, name_pattern, inq, logger))
    for w in workers:
        w.start()
    logger.info("RabbitMQ backbone started.")


@threatbus.backbone
def stop():
    global logger, workers
    for w in workers:
        if not w.is_alive():
            continue
        w.stop()
        w.join()
    logger.info("RabbitMQ backbone stopped")
