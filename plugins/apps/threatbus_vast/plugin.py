from queue import Queue
import random
import string
import threading
from threatbus_vast.message_mapping import map_management_message
import threatbus
from threatbus.data import Subscription, Unsubscription
import zmq


"""VAST network telemetry engine - plugin for Threat Bus"""

plugin_name = "vast"
lock = threading.Lock()
subscriptions = dict()


def validate_config(config):
    assert config, "config must not be None"
    config["zmq_manage"].get(dict)
    config["zmq_manage"]["host"].get(str)
    config["zmq_manage"]["port"].get(int)
    config["zmq_pubsub"].get(dict)
    config["zmq_pubsub"]["host"].get(str)
    config["zmq_pubsub"]["port"].get(int)


def rand_string(length):
    """Generates a pseudo-random string with the requested length"""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


def receive_management(
    zmq_manage_config, zmq_pubsub_config, subscribe_callback, unsubscribe_callback
):
    """Management message endpoint"""
    global logger, lock, subscriptions

    context = zmq.Context()
    socket = context.socket(zmq.REP)  # REP socket for point-to-point reply
    socket.bind(f"tcp://{zmq_manage_config['host']}:{zmq_manage_config['port']}")
    rand_suffix_length = 10
    pubsub_endpoint = f"{zmq_pubsub_config['host']}:{zmq_pubsub_config['port']}"

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
            subscribe_callback(task.topic, p2p_q, task.snapshot)
            lock.acquire()
            subscriptions[p2p_topic] = p2p_q
            lock.release()
            # send success message for reconnecting
            socket.send_json({"topic": p2p_topic, "endpoint": pubsub_endpoint})
        elif isinstance(task, Unsubscription):
            logger.debug(f"Received unsubscription from topic {task.topic}")
            threatbus_topic = task.topic[: len(task.topic) - rand_suffix_length]
            p2p_q = subscriptions.get(task.topic, None)
            if p2p_q:
                unsubscribe_callback(threatbus_topic, p2p_q)
                lock.acquire()
                del subscriptions[task.topic]
                lock.release()
            socket.send_string("Unsubscribe success")
        else:
            socket.send_string("Unknown request")


@threatbus.app
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
    global logger
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    zmq_manage, zmq_pubsub = (
        config["zmq_manage"].get(),
        config["zmq_pubsub"].get(),
    )
    threading.Thread(
        target=receive_management,
        args=(zmq_manage, zmq_pubsub, subscribe_callback, unsubscribe_callback),
        daemon=True,
    ).start()
    logger.info(f"VAST plugin started")
