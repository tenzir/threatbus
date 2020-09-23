import json
from queue import Queue
import random
import string
import threading
from threatbus_zmq_app.message_mapping import map_management_message
import threatbus
from threatbus.data import (
    Subscription,
    Unsubscription,
    IntelEncoder,
    SightingDecoder,
    Sighting,
)
import time
import zmq


"""
ZeroMQ application plugin for Threat Bus.
Allows to connect any app via ZeroMQ that adheres to the Threat Bus ZMQ protocol.
"""

plugin_name = "zmq-app"
lock = threading.Lock()
subscriptions = dict()


def validate_config(config):
    assert config, "config must not be None"
    config["host"].get(str)
    config["manage"].get(int)
    config["pub"].get(int)
    config["sub"].get(int)


def rand_string(length):
    """Generates a pseudo-random string with the requested length"""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


def receive_management(zmq_config, subscribe_callback, unsubscribe_callback):
    """
    Management endpoint to handle (un)subscriptions of apps.
    @param zmq_config Config object for the ZeroMQ endpoints
    @param subscribe_callback Callback from Threat Bus to unsubscribe new apps
    @param unsubscribe_callback Callback from Threat Bus to unsubscribe apps
    """
    global logger, lock, subscriptions

    context = zmq.Context()
    socket = context.socket(zmq.REP)  # REP socket for point-to-point reply
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['manage']}")
    rand_suffix_length = 10
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

        if isinstance(task, Subscription):
            # point-to-point topic and queue for that particular subscription
            p2p_topic = task.topic + rand_string(rand_suffix_length)
            p2p_q = Queue()
            logger.debug(
                f"Received subscription for topic {task.topic}, snapshot {task.snapshot}"
            )
            # send success message for reconnecting
            socket.send_json(
                {
                    "topic": p2p_topic,
                    "pub_endpoint": pub_endpoint,
                    "sub_endpoint": sub_endpoint,
                }
            )
            lock.acquire()
            subscriptions[p2p_topic] = p2p_q
            lock.release()
            subscribe_callback(task.topic, p2p_q, task.snapshot)
        elif isinstance(task, Unsubscription):
            logger.debug(f"Received unsubscription from topic {task.topic}")
            threatbus_topic = task.topic[: len(task.topic) - rand_suffix_length]
            p2p_q = subscriptions.get(task.topic, None)
            if p2p_q:
                unsubscribe_callback(threatbus_topic, p2p_q)
                lock.acquire()
                del subscriptions[task.topic]
                lock.release()
            socket.send_string("Success")
        else:
            socket.send_string("Unknown request")


def pub_zmq(zmq_config):
    global subscriptions, lock, logger
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['pub']}")

    while True:
        lock.acquire()
        subs_copy = subscriptions.copy()
        lock.release()
        for topic, q in subs_copy.items():
            if q.empty():
                continue
            msg = q.get()
            if not msg:
                continue
            intel_json = json.dumps(msg, cls=IntelEncoder)
            socket.send((f"{topic} {intel_json}").encode())
            logger.debug(f"Published {intel_json} on topic {topic}")
            q.task_done()
        time.sleep(0.05)


def sub_zmq(zmq_config, inq):
    global logger
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['sub']}")
    socket.setsockopt(zmq.SUBSCRIBE, b"sightings")

    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    while True:
        socks = dict(poller.poll(timeout=None))
        if socket in socks and socks[socket] == zmq.POLLIN:
            try:
                _, msg = socket.recv().decode().split(" ", 1)
                sighting = json.loads(msg, cls=SightingDecoder)
                if type(sighting) is not Sighting:
                    logger.warn(
                        f"Ignoring unknown message type, expected Sighting: {type(sighting)}"
                    )
                    continue
                inq.put(sighting)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue


@threatbus.app
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
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
