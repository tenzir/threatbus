from confuse import Subview
import json
from multiprocessing import JoinableQueue
import random
import select
import string
import threading
from threatbus_zmq_app.message_mapping import Heartbeat, map_management_message
import threatbus
from threatbus.data import (
    Intel,
    IntelDecoder,
    IntelEncoder,
    Sighting,
    SightingDecoder,
    SightingEncoder,
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

plugin_name = "zmq-app"
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
        zmq_config: Subview,
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
        socket.bind(f"tcp://{self.zmq_config['host']}:{self.zmq_config['manage']}")
        pub_endpoint = f"{self.zmq_config['host']}:{self.zmq_config['pub']}"
        sub_endpoint = f"{self.zmq_config['host']}:{self.zmq_config['sub']}"

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
                        snapshot_id = self.subscribe_callback(
                            task.topic, p2p_q, task.snapshot
                        )
                        if snapshot_id:
                            # remember that this snapshot was requested by this particular
                            # subscriber (identified by unique topic), so it is not asked to
                            # execute it's own request
                            snapshots_lock.acquire()
                            snapshots[snapshot_id] = p2p_topic
                            snapshots_lock.release()
                        # send success message for reconnecting
                        socket.send_json(
                            {
                                "topic": p2p_topic,
                                "pub_endpoint": pub_endpoint,
                                "sub_endpoint": sub_endpoint,
                                "status": "success",
                            }
                        )
                    except Exception as e:
                        logger.error(f"Error handling subscription request {task}: {e}")
                        socket.send_json({"status": "error"})
                elif type(task) is Unsubscription:
                    logger.info(f"Received unsubscription from topic {task.topic}")
                    threatbus_topic, p2p_q = subscriptions.get(task.topic, (None, None))
                    if not p2p_q:
                        logger.warn("No one was subscribed for that topic. Skipping.")
                        socket.send_json({"status": "error"})
                        continue
                    self.unsubscribe_callback(threatbus_topic, p2p_q)
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

    def __init__(self, zmq_config: Subview):
        """
        @param zmq_config ZeroMQ configuration properties
        """
        super(ZmqPublisher, self).__init__()
        self.zmq_config = zmq_config

    def run(self):
        global subscriptions, subscriptions_lock, logger
        context = zmq.Context()
        socket = context.socket(zmq.PUB)
        socket.bind(f"tcp://{self.zmq_config['host']}:{self.zmq_config['pub']}")

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
                if type(msg) is Intel:
                    encoded = json.dumps(msg, cls=IntelEncoder)
                    topic += "intel"
                elif type(msg) is Sighting:
                    encoded = json.dumps(msg, cls=SightingEncoder)
                    topic += "sighting"
                elif type(msg) is SnapshotRequest:
                    encoded = json.dumps(msg, cls=SnapshotRequestEncoder)
                    topic += "snapshotrequest"
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

    def __init__(self, zmq_config: Subview, inq: JoinableQueue):
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
        socket.bind(f"tcp://{self.zmq_config['host']}:{self.zmq_config['sub']}")
        intel_topic = "threatbus/intel"
        sighting_topic = "threatbus/sighting"
        snapshotenvelope_topic = "threatbus/snapshotenvelope"
        socket.setsockopt(zmq.SUBSCRIBE, intel_topic.encode())
        socket.setsockopt(zmq.SUBSCRIBE, sighting_topic.encode())
        socket.setsockopt(zmq.SUBSCRIBE, snapshotenvelope_topic.encode())

        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        while self._running():
            socks = dict(poller.poll(timeout=1000))
            if socket not in socks or socks[socket] != zmq.POLLIN:
                continue
            try:
                topic, msg = socket.recv().decode().split(" ", 1)
                if topic == intel_topic:
                    decoded = json.loads(msg, cls=IntelDecoder)
                    if type(decoded) is not Intel:
                        logger.warn(
                            f"Ignoring unknown message type, expected Intel: {type(decoded)}"
                        )
                        continue
                elif topic == sighting_topic:
                    decoded = json.loads(msg, cls=SightingDecoder)
                    if type(decoded) is not Sighting:
                        logger.warn(
                            f"Ignoring unknown message type, expected Sighting: {type(decoded)}"
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


def validate_config(config: Subview):
    assert config, "config must not be None"
    config["host"].get(str)
    config["manage"].get(int)
    config["pub"].get(int)
    config["sub"].get(int)


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
    config: Subview,
    logging: Subview,
    inq: JoinableQueue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    global logger, workers
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
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
