import broker
from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
from multiprocessing import JoinableQueue
import random
import select
import string
import threading
import threatbus
from threatbus.data import Subscription, Unsubscription
from threatbus_zeek.message_mapping import (
    map_indicator_to_broker_event,
    map_broker_event_to_sighting,
    map_management_message,
)
from typing import Callable, Dict, List, Union

"""Zeek network monitor - plugin for Threat Bus"""

plugin_name = "zeek"
lock = threading.Lock()
subscriptions: Dict[str, JoinableQueue] = dict()  # p2p_topic => queue
workers: List[threatbus.StoppableWorker] = list()


class SubscriptionManager(threatbus.StoppableWorker):
    def __init__(
        self,
        module_namespace: str,
        ep: broker.Endpoint,
        subscribe_callback: Callable,
        unsubscribe_callback: Callable,
    ):
        """
        @param module_namespace A Zeek namespace to accept events from
        @param ep The broker endpoint used for listening
        @param subscribe_callback The callback to invoke for new subscriptions
        @param unsubscribe_callback The callback to invoke for revoked subscriptions
        """
        super(SubscriptionManager, self).__init__()
        self.ep = ep
        self.module_namespace = module_namespace
        self.subscribe_callback = subscribe_callback
        self.unsubscribe_callback = unsubscribe_callback
        self.rand_suffix_length = 10

    def run(self):
        """
        Binds a broker subscriber to the given endpoint. Only listens for management
        messages, such as un/subscriptions of new clients.
        """
        global logger
        sub = self.ep.make_subscriber("threatbus/manage")
        while self._running():
            (ready_readers, [], []) = select.select([sub.fd()], [], [], 1)
            if not ready_readers:
                continue
            (topic, broker_data) = sub.get()
            msg = map_management_message(broker_data, self.module_namespace, logger)
            if msg:
                self.manage_subscription(msg)

    def rand_string(self, length):
        """
        Generates a pseudo-random string with the requested length
        """
        letters = string.ascii_lowercase
        return "".join(random.choice(letters) for i in range(length))

    def manage_subscription(self, task: Union[Subscription, Unsubscription]):
        """
        Manages subscriptions and unsubscriptions of Zeek instances.
        @param task A Subscription or Unsubscription request of a Zeek instance
        """
        global lock, subscriptions
        if type(task) is Subscription:
            # point-to-point topic and queue for that particular subscription
            logger.info(
                f"Received subscription for topic '{task.topic}' with snapshot '{task.snapshot}'"
            )
            p2p_topic = task.topic + self.rand_string(self.rand_suffix_length)
            p2p_q = JoinableQueue()
            ack = broker.zeek.Event(
                f"{self.module_namespace}::subscription_acknowledged", p2p_topic
            )
            self.ep.publish("threatbus/manage", ack)
            self.subscribe_callback(task.topic, p2p_q, task.snapshot)
            lock.acquire()
            subscriptions[p2p_topic] = p2p_q
            lock.release()
        elif type(task) is Unsubscription:
            logger.info(f"Received unsubscription from topic '{task.topic}'")
            threatbus_topic = task.topic[: len(task.topic) - self.rand_suffix_length]
            p2p_q = subscriptions.get(task.topic, None)
            if not p2p_q:
                logger.warning(f"No one was subscribed for topic '{task.topic}'")
                return
            self.unsubscribe_callback(threatbus_topic, p2p_q)
            lock.acquire()
            del subscriptions[task.topic]
            lock.release()
        else:
            logger.debug(f"Skipping unknown management message of type: {type(task)}")


class BrokerPublisher(threatbus.StoppableWorker):
    """
    Publishes messages for all subscriptions in a round-robin fashion to via
    broker.
    """

    def __init__(self, module_namespace: str, ep: broker.Endpoint):
        """
        @param module_namespace A Zeek namespace to use for event sending
        @param ep The broker endpoint used for publishing
        """
        super(BrokerPublisher, self).__init__()
        self.module_namespace = module_namespace
        self.ep = ep

    def run(self):
        global subscriptions, lock, logger
        while self._running():
            lock.acquire()
            # subscriptions is a dict with p2p_topic => queue
            # qt_lookup is a dict with queue-reader => (p2p_topic, queue)
            qt_lookup = {
                sub[1]._reader: (sub[0], sub[1]) for sub in subscriptions.items()
            }
            readers = [q._reader for q in subscriptions.values()]
            lock.release()
            (ready_readers, [], []) = select.select(readers, [], [], 1)
            for fd in ready_readers:
                topic, q = qt_lookup[fd]
                if q.empty():
                    continue
                msg = q.get()
                if not msg:
                    q.task_done()
                    continue
                try:
                    event = map_indicator_to_broker_event(
                        msg, self.module_namespace, logger
                    )
                    if event:
                        self.ep.publish(topic, event)
                        logger.debug(f"Published {msg} on topic {topic}")
                except Exception as e:
                    logger.error(f"Error publishing message to broker {msg}: {e}")
                finally:
                    q.task_done()


class BrokerReceiver(threatbus.StoppableWorker):
    """
    Binds a broker subscriber to the given endpoint. Forwards all received
    sightings to the inq.
    """

    def __init__(self, module_namespace: str, ep: broker.Endpoint, inq: JoinableQueue):
        """
        @param module_namespace A Zeek namespace to accept events from
        @param ep The broker endpoint used for listening
        @param inq The queue to forward messages to
        """
        super(BrokerReceiver, self).__init__()
        self.module_namespace = module_namespace
        self.ep = ep
        self.inq = inq

    def run(self):
        """
        Spawns a Broker endpoint and listens for sightings. Converts sightings
        from the Zeek format to STIX-2 Sightings and forwards them to Threat Bus
        """
        sub = self.ep.make_subscriber(["stix2/sighting"])
        global logger
        while self._running():
            (ready_readers, [], []) = select.select([sub.fd()], [], [], 1)
            if not ready_readers:
                continue
            (topic, broker_data) = sub.get()
            try:
                msg = map_broker_event_to_sighting(
                    broker_data, self.module_namespace, logger
                )
                if msg:
                    logger.debug(f"Received sighting {msg}")
                    self.inq.put(msg)
            except Exception as e:
                logger.error(f"Error mapping Broker event to STIX-2 Sighting: {e}")


@threatbus.app
def config_validators() -> List[Validator]:
    return [
        Validator(
            f"plugins.apps.{plugin_name}.host",
            is_type_of=str,
            default="localhost",
        ),
        Validator(
            f"plugins.apps.{plugin_name}.module_namespace",
            is_type_of=str,
            default="Tenzir",
        ),
        Validator(
            f"plugins.apps.{plugin_name}.port",
            is_type_of=int,
            default=47761,
        ),
    ]


@threatbus.app
def run(
    config: DynaBox,
    logging: DynaBox,
    inq: JoinableQueue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    global logger, workers
    logger = threatbus.logger.setup(logging, __name__)
    assert plugin_name in config, f"Cannot find configuration for {plugin_name} plugin"
    config = config[plugin_name]

    broker_opts = broker.BrokerOptions()
    broker_opts.forward = False
    ep = broker.Endpoint(broker.Configuration(broker_opts))
    ep.listen(config.host, config.port)

    workers.append(
        SubscriptionManager(
            config.module_namespace, ep, subscribe_callback, unsubscribe_callback
        )
    )
    workers.append(BrokerReceiver(config.module_namespace, ep, inq))
    workers.append(BrokerPublisher(config.module_namespace, ep))
    for w in workers:
        w.start()
    logger.info("Zeek plugin started")


@threatbus.app
def stop():
    global logger, workers
    for w in workers:
        if not w.is_alive():
            continue
        w.stop()
        w.join()
    logger.info("Zeek plugin stopped")
