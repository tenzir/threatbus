from confuse import Subview
import json
from queue import Queue
import random
import string
import threading
from threatbus_zmq_app.message_mapping import map_management_message
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
import time
from typing import Callable, Dict, Tuple
import zmq


"""
ZeroMQ application plugin for Threat Bus.
Allows to connect any app via ZeroMQ that adheres to the Threat Bus ZMQ protocol.
"""

plugin_name = "zmq-app"
subscriptions_lock = threading.Lock()
subscriptions: Dict[str, Tuple[str, Queue]] = dict()  # p2p_topic => (topic, queue)
snapshots_lock = threading.Lock()
snapshots: Dict[str, str] = dict()  # snapshot_id => topic
p2p_topic_prefix_length = 32  # length of random topic prefix


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


def receive_management(
    zmq_config: Subview, subscribe_callback: Callable, unsubscribe_callback: Callable
):
    """
    Management endpoint to handle (un)subscriptions of apps.
    @param zmq_config Config object for the ZeroMQ endpoints
    @param subscribe_callback Callback from Threat Bus to unsubscribe new apps
    @param unsubscribe_callback Callback from Threat Bus to unsubscribe apps
    """
    global logger, subscriptions_lock, subscriptions, snapshots_lock, snapshots

    context = zmq.Context()
    socket = context.socket(zmq.REP)  # REP socket for point-to-point reply
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['manage']}")
    pub_endpoint = f"{zmq_config['host']}:{zmq_config['pub']}"
    sub_endpoint = f"{zmq_config['host']}:{zmq_config['sub']}"

    while True:
        #  Wait for next request from client
        try:
            msg = socket.recv_json()
        except Exception as e:
            logger.error(f"Error decoding message {msg}: {e}")
            continue
        task = map_management_message(msg)

        if type(task) is Subscription:
            # point-to-point topic and queue for that particular subscription
            try:
                p2p_topic = rand_string(p2p_topic_prefix_length)
                p2p_q = Queue()
                logger.info(
                    f"Received subscription for topic {task.topic}, snapshot {task.snapshot}"
                )
                subscriptions_lock.acquire()
                subscriptions[p2p_topic] = (task.topic, p2p_q)
                subscriptions_lock.release()
                snapshot_id = subscribe_callback(task.topic, p2p_q, task.snapshot)
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
            unsubscribe_callback(threatbus_topic, p2p_q)
            subscriptions_lock.acquire()
            del subscriptions[task.topic]
            subscriptions_lock.release()
            socket.send_json({"status": "success"})
        else:
            socket.send_json({"status": "unknown request"})


def pub_zmq(zmq_config: Subview):
    """
    Publshes messages to all registered subscribers via ZeroMQ.
    @param zmq_config ZeroMQ configuration properties
    """
    global subscriptions, subscriptions_lock, logger
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['pub']}")

    while True:
        subscriptions_lock.acquire()
        subs_copy = subscriptions.copy()
        subscriptions_lock.release()
        # the queues are filled by the backbone, the plugin distributes all
        # messages in round-robin fashion to all subscribers
        for topic, (_, q) in subs_copy.items():
            if q.empty():
                continue
            msg = q.get()
            if not msg:
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
                continue
            socket.send((f"{topic} {encoded}").encode())
            logger.debug(f"Published {encoded} on topic {topic}")
            q.task_done()
        time.sleep(0.05)


def sub_zmq(zmq_config: Subview, inq: Queue):
    """
    Forwards messages that are received via ZeroMQ from connected applications
    to the plugin's in-queue.
    @param zmq_config ZeroMQ configuration properties
    """
    global logger
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['sub']}")
    intel_topic = "threatbus/intel"
    sighting_topic = "threatbus/sighting"
    snapshotenvelope_topic = "threatbus/snapshotenvelope"
    socket.setsockopt(zmq.SUBSCRIBE, intel_topic.encode())
    socket.setsockopt(zmq.SUBSCRIBE, sighting_topic.encode())
    socket.setsockopt(zmq.SUBSCRIBE, snapshotenvelope_topic.encode())

    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    while True:
        socks = dict(poller.poll(timeout=None))
        if socket in socks and socks[socket] == zmq.POLLIN:
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

                inq.put(decoded)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue


@threatbus.app
def snapshot(snapshot_request: SnapshotRequest, result_q: Queue):
    global logger, snapshots, snapshots_lock, subscriptions, subscriptions_lock
    logger.info(f"Executing snapshot for time delta {snapshot_request.snapshot}")

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
    inq: Queue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    global logger
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    threading.Thread(target=pub_zmq, args=(config,), daemon=True).start()
    threading.Thread(target=sub_zmq, args=(config, inq), daemon=True).start()
    threading.Thread(
        target=receive_management,
        args=(config, subscribe_callback, unsubscribe_callback),
        daemon=True,
    ).start()
    logger.info("ZeroMQ app plugin started")
