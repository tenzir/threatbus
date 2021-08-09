from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
import json
from multiprocessing import JoinableQueue
import random
import select
from stix2 import Indicator, Sighting, parse
import string
import threading
from threatbus_zmq.message_mapping import Heartbeat, map_management_message
import threatbus
from threatbus.data import (
    SnapshotEnvelope,
    SnapshotEnvelopeDecoder,
    SnapshotRequest,
    SnapshotRequestEncoder,
    Subscription,
    Unsubscription,
)
from typing import Callable, Dict, List, Tuple
import zmq


"""
ZeroMQ application plugin for Threat Bus.
Allows to connect any app via ZeroMQ that adheres to the Threat Bus ZMQ protocol.
"""

plugin_name = "zmq"
subscriptions_lock = threading.Lock()
# subscriptions: p2p_topic => (topic, queue)
subscriptions: Dict[str, Tuple[str, JoinableQueue]] = dict()
snapshots_lock = threading.Lock()
snapshots: Dict[str, str] = dict()  # snapshot_id => topic
p2p_topic_prefix_length = 32  # length of random topic prefix
workers: List[threatbus.StoppableWorker] = list()


class SubscriptionManager(threatbus.StoppableWorker):
    """
    Management endpoint to handle (un)subscriptions of apps.
    """

    def __init__(
        self,
        zmq_config: DynaBox,
        subscribe_callback: Callable,
        unsubscribe_callback: Callable,
    ):
        """
        @param zmq_config Config object for the ZeroMQ endpoints
        @param subscribe_callback Callback from Threat Bus to unsubscribe new apps
        @param unsubscribe_callback Callback from Threat Bus to unsubscribe apps
        """
        super(SubscriptionManager, self).__init__()
        self.zmq_config = zmq_config
        self.subscribe_callback = subscribe_callback
        self.unsubscribe_callback = unsubscribe_callback

    def run(self):
        global logger, subscriptions_lock, subscriptions, snapshots_lock, snapshots

        context = zmq.Context()
        socket = context.socket(zmq.REP)  # REP socket for point-to-point reply
        socket.bind(f"tcp://{self.zmq_config.host}:{self.zmq_config.manage}")

        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        while self._running():
            socks = dict(poller.poll(timeout=1000))
            if socket not in socks or socks[socket] != zmq.POLLIN:
                continue
            try:
                msg = None
                msg = socket.recv_json()
                task = map_management_message(msg)

                if type(task) is Subscription:
                    # point-to-point topic and queue for that particular subscription
                    logger.info(
                        f"Received subscription for topic {task.topic}, snapshot {task.snapshot}"
                    )
                    try:
                        p2p_topic = rand_string(p2p_topic_prefix_length)
                        p2p_q = JoinableQueue()
                        subscriptions_lock.acquire()
                        subscriptions[p2p_topic] = (task.topic, p2p_q)
                        subscriptions_lock.release()
                        subscribed_topics = (
                            task.topic if type(task.topic) is list else [task.topic]
                        )

                        for subscribed_topic in subscribed_topics:
                            snapshot_id = self.subscribe_callback(
                                subscribed_topic, p2p_q, task.snapshot
                            )
                            if snapshot_id:
                                # remember that this snapshot was requested by this particular
                                # subscriber (identified by unique p2p_topic), so it is not asked to
                                # execute it's own snapshot request
                                snapshots_lock.acquire()
                                snapshots[snapshot_id] = p2p_topic
                                snapshots_lock.release()
                        # send success message for reconnecting
                        socket.send_json(
                            {
                                "topic": p2p_topic,
                                "pub_port": self.zmq_config.pub,
                                "sub_port": self.zmq_config.sub,
                                "status": "success",
                            }
                        )
                    except Exception as e:
                        logger.error(f"Error handling subscription request {task}: {e}")
                        socket.send_json({"status": "error"})
                elif type(task) is Unsubscription:
                    logger.info(f"Received unsubscription from topic {task.topic}")
                    threatbus_topics, p2p_q = subscriptions.get(
                        task.topic, (None, None)
                    )
                    threatbus_topics = (
                        threatbus_topics
                        if type(threatbus_topics) is list
                        else [threatbus_topics]
                    )
                    if not p2p_q:
                        logger.warn("No one was subscribed for that topic. Skipping.")
                        socket.send_json({"status": "error"})
                        continue
                    for tb_topic in threatbus_topics:
                        self.unsubscribe_callback(tb_topic, p2p_q)
                    subscriptions_lock.acquire()
                    del subscriptions[task.topic]
                    subscriptions_lock.release()
                    socket.send_json({"status": "success"})
                elif type(task) is Heartbeat:
                    if task.topic not in subscriptions:
                        socket.send_json({"status": "error"})
                        continue
                    socket.send_json({"status": "success"})
                else:
                    socket.send_json({"status": "unknown request"})
            except Exception as e:
                socket.send_json({"status": "error"})
                logger.error(f"Error handling management message {msg}: {e}")


class ZmqPublisher(threatbus.StoppableWorker):
    """
    Publshes messages to all registered subscribers via ZeroMQ.
    """

    def __init__(self, zmq_config: DynaBox):
        """
        @param zmq_config ZeroMQ configuration properties
        """
        super(ZmqPublisher, self).__init__()
        self.zmq_config = zmq_config

    def run(self):
        global subscriptions, subscriptions_lock, logger
        context = zmq.Context()
        socket = context.socket(zmq.PUB)
        socket.bind(f"tcp://{self.zmq_config.host}:{self.zmq_config.pub}")

        while self._running():
            subscriptions_lock.acquire()
            # subscriptions is a dict with p2p_topic => (topic, queue)
            # qt_lookup is a dict with queue-reader => (topic, queue)
            qt_lookup = {
                sub[1][1]._reader: (sub[0], sub[1][1]) for sub in subscriptions.items()
            }
            readers = [tq[1]._reader for tq in subscriptions.values()]
            subscriptions_lock.release()
            (ready_readers, [], []) = select.select(readers, [], [], 1)
            for fd in ready_readers:
                topic, q = qt_lookup[fd]
                if q.empty():
                    continue
                msg = q.get()
                if not msg:
                    q.task_done()
                    continue
                topic += type(msg).__name__.lower()
                if type(msg) is Indicator or type(msg) is Sighting:
                    encoded = msg.serialize()
                elif type(msg) is SnapshotRequest:
                    encoded = json.dumps(msg, cls=SnapshotRequestEncoder)
                else:
                    logger.warn(
                        f"Skipping unknown message type '{type(msg)}' for topic subscription {topic}."
                    )
                    q.task_done()
                    continue
                try:
                    socket.send((f"{topic} {encoded}").encode())
                    logger.debug(f"Published {encoded} on topic {topic}")
                except Exception as e:
                    logger.error(f"Error sending {encoded} on topic {topic}: {e}")
                finally:
                    q.task_done()


class ZmqReceiver(threatbus.StoppableWorker):
    """
    Forwards messages that are received via ZeroMQ from connected applications
    to the plugin's in-queue.
    """

    def __init__(self, zmq_config: DynaBox, inq: JoinableQueue):
        """
        @param zmq_config ZeroMQ configuration properties
        """
        super(ZmqReceiver, self).__init__()
        self.zmq_config = zmq_config
        self.inq = inq

    def run(self):
        global logger
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        socket.bind(f"tcp://{self.zmq_config.host}:{self.zmq_config.sub}")
        stix2_topic_prefix = "stix2/"
        snapshotenvelope_topic = "threatbus/snapshotenvelope"
        socket.setsockopt(zmq.SUBSCRIBE, stix2_topic_prefix.encode())
        socket.setsockopt(zmq.SUBSCRIBE, snapshotenvelope_topic.encode())

        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        while self._running():
            socks = dict(poller.poll(timeout=1000))
            if socket not in socks or socks[socket] != zmq.POLLIN:
                continue
            try:
                topic, msg = socket.recv().decode().split(" ", 1)
                if topic.startswith(stix2_topic_prefix):
                    decoded = parse(msg, allow_custom=True)
                    if type(decoded) is not Indicator and type(decoded) is not Sighting:
                        logger.warn(
                            f"Ignoring unknown message type, expected STIX-2 Indicator or Sighting: {type(decoded)}"
                        )
                        continue
                elif topic == snapshotenvelope_topic:
                    decoded = json.loads(msg, cls=SnapshotEnvelopeDecoder)
                    if type(decoded) is not SnapshotEnvelope:
                        logger.warn(
                            f"Ignoring unknown message type, expected SnapshotEnvelope: {type(decoded)}"
                        )
                        continue

                self.inq.put(decoded)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue


@threatbus.app
def config_validators() -> List[Validator]:
    return [
        Validator(f"plugins.apps.{plugin_name}.host", required=True),
        Validator(
            f"plugins.apps.{plugin_name}.manage",
            f"plugins.apps.{plugin_name}.pub",
            f"plugins.apps.{plugin_name}.sub",
            is_type_of=int,
            required=True,
        ),
    ]


def rand_string(length: int):
    """Generates a pseudo-random string with the requested length"""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


@threatbus.app
def snapshot(snapshot_request: SnapshotRequest, result_q: JoinableQueue):
    global logger, snapshots, snapshots_lock, subscriptions, subscriptions_lock

    snapshots_lock.acquire()
    requester = snapshots.get(snapshot_request.snapshot_id, None)
    snapshots_lock.release()

    subscriptions_lock.acquire()
    subs_copy = subscriptions.copy()
    subscriptions_lock.release()
    # push the request into every subscribed queue, except the requester's
    for topic, (_, q) in subs_copy.items():
        if topic == requester:
            continue
        q.put(snapshot_request)


@threatbus.app
def run(
    config: DynaBox,
    logging: DynaBox,
    inq: JoinableQueue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    global logger, workers
    assert plugin_name in config, f"Cannot find configuration for {plugin_name} plugin"
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    workers.append(ZmqPublisher(config))
    workers.append(ZmqReceiver(config, inq))
    workers.append(
        SubscriptionManager(config, subscribe_callback, unsubscribe_callback)
    )
    for w in workers:
        w.start()
    logger.info("ZeroMQ app plugin started")


@threatbus.app
def stop():
    global logger, workers
    for w in workers:
        if not w.is_alive():
            continue
        w.stop()
        w.join()
    logger.info("ZeroMQ app plugin stopped")
