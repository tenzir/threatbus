from collections import defaultdict
from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
from multiprocessing import JoinableQueue
import pika
from retry import retry
from socket import gethostname
from stix2 import Indicator, Sighting
import threading
import threatbus
from threatbus.data import SnapshotRequest, SnapshotEnvelope
from threatbus_rabbitmq import RabbitMQConsumer, RabbitMQPublisher
from typing import Dict, List, Union

"""RabbitMQ backbone plugin for Threat Bus"""

plugin_name = "rabbitmq"

subscriptions: Dict[str, set] = defaultdict(set)
lock = threading.Lock()
workers: List[threatbus.StoppableWorker] = list()


def provision(
    topic: str, msg: Union[Indicator, Sighting, SnapshotEnvelope, SnapshotRequest]
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


@threatbus.backbone
def config_validators() -> List[Validator]:
    return [
        Validator(
            f"plugins.backbones.{plugin_name}.host",
            f"plugins.backbones.{plugin_name}.username",
            f"plugins.backbones.{plugin_name}.password",
            is_type_of=str,
            required=True,
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.vhost",
            is_type_of=str,
            default="/",
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.exchange_name",
            default="threatbus",
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.port",
            is_type_of=int,
            required=True,
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.queue.durable",
            f"plugins.backbones.{plugin_name}.queue.lazy",
            is_type_of=bool,
            default=True,
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.queue.auto_delete",
            f"plugins.backbones.{plugin_name}.queue.exclusive",
            is_type_of=bool,
            default=False,
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.queue.name_join_symbol",
            required=True,
            default=".",
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.queue.name_suffix",
            default=gethostname(),
        ),
        Validator(
            f"plugins.backbones.{plugin_name}.queue.max_items",
            is_type_of=int,
            default=0,
        ),
    ]


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
def run(config: DynaBox, logging: DynaBox, inq: JoinableQueue):
    global subscriptions, lock, logger, workers
    assert plugin_name in config, f"Cannot find configuration for {plugin_name} plugin"
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    credentials = pika.PlainCredentials(config.username, config.password)
    conn_params = pika.ConnectionParameters(
        config.host, config.port, config.vhost, credentials
    )
    workers.append(
        RabbitMQConsumer(
            conn_params, config.exchange_name, config.queue, provision, logger
        )
    )
    workers.append(RabbitMQPublisher(conn_params, config.exchange_name, inq, logger))
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
