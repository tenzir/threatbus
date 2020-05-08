import json
from queue import Queue
import random
import string
import threading
from threatbus_vast.message_mapping import (
    map_management_message,
    map_intel_to_vast,
    map_vast_sighting,
)
import threatbus
from threatbus.data import Subscription, Unsubscription
import time
import zmq


"""VAST network telemetry engine - plugin for Threat Bus"""

plugin_name = "vast"
lock = threading.Lock()
subscriptions = dict()


def validate_config(config):
    assert config, "config must not be None"
    config["zmq"].get(dict)
    config["zmq"]["host"].get(str)
    config["zmq"]["manage"].get(int)
    config["zmq"]["pub"].get(int)
    config["zmq"]["sub"].get(int)


def rand_string(length):
    """Generates a pseudo-random string with the requested length"""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


def receive_management(zmq_config, subscribe_callback, unsubscribe_callback):
    """
        Management endpoint to handle (un)subscriptions of VAST-bridge
        instances.
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
        for topic, q in subscriptions.items():
            if q.empty():
                continue
            msg = q.get()
            if not msg:
                continue
            intel = map_intel_to_vast(msg)
            socket.send((f"{topic} {intel}").encode())
        lock.release()
        time.sleep(0.05)


def sub_zmq(zmq_config, inq):
    global logger
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['sub']}")
    socket.setsockopt(zmq.SUBSCRIBE, b"vast/sightings")

    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    while True:
        socks = dict(poller.poll(timeout=None))
        if socket in socks and socks[socket] == zmq.POLLIN:
            try:
                _, msg = socket.recv().decode().split(" ", 1)
                msg = json.loads(msg)
                sighting = map_vast_sighting(msg)
                if not sighting:
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
    threading.Thread(target=pub_zmq, args=(config["zmq"],), daemon=True).start()
    threading.Thread(target=sub_zmq, args=(config["zmq"], inq), daemon=True).start()
    threading.Thread(
        target=receive_management,
        args=(config["zmq"], subscribe_callback, unsubscribe_callback),
        daemon=True,
    ).start()
    logger.info(f"VAST plugin started")
