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
    Intel,
    IntelDecoder,
    IntelEncoder,
    Sighting,
    SightingDecoder,
    SightingEncoder,
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
    rand_prefix_length = 10
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
            p2p_topic = rand_string(rand_prefix_length) + task.topic
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
                    "status": "success",
                }
            )
            lock.acquire()
            subscriptions[p2p_topic] = p2p_q
            lock.release()
            subscribe_callback(task.topic, p2p_q, task.snapshot)
        elif type(task) is Unsubscription:
            if not len(task.topic) > rand_prefix_length:
                logger.warn("Skipping invalid unsubscription")
                socket.send_json({"status": "unsuccess"})
                continue
            threatbus_topic = task.topic[rand_prefix_length:]
            logger.debug(f"Received unsubscription from topic {threatbus_topic}")
            p2p_q = subscriptions.get(task.topic, None)
            if p2p_q:
                unsubscribe_callback(threatbus_topic, p2p_q)
                lock.acquire()
                del subscriptions[task.topic]
                lock.release()
            socket.send_json({"status": "success"})
        else:
            socket.send_json({"status": "unknown request"})


def pub_zmq(zmq_config):
    """
    Publshes messages to all registered subscribers via ZeroMQ.
    @param zmq_config ZeroMQ configuration properties
    """
    global subscriptions, lock, logger
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['pub']}")

    while True:
        lock.acquire()
        subs_copy = subscriptions.copy()
        lock.release()
        # the queues are filled by the backbone, the plugin distributes all
        # messages in round-robin fashion to all subscribers
        for topic, q in subs_copy.items():
            if q.empty():
                continue
            msg = q.get()
            if not msg:
                continue
            if type(msg) is Intel:
                encoded = json.dumps(msg, cls=IntelEncoder)
            elif type(msg) is Sighting:
                encoded = json.dumps(msg, cls=SightingEncoder)
            else:
                logger.warn(
                    f"Skipping unknown message type '{type(msg)}' for topic subscription {topic}."
                )
                continue
            socket.send((f"{topic} {encoded}").encode())
            logger.debug(f"Published {encoded} on topic {topic}")
            q.task_done()
        time.sleep(0.05)


def sub_zmq(zmq_config, inq):
    """
    Forwards messages, that are received via ZeroMQ from connected applications,
    to the plugin's in-queue.
    @param zmq_config ZeroMQ configuration properties
    """
    global logger
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.bind(f"tcp://{zmq_config['host']}:{zmq_config['sub']}")
    intel_topic = "threatbus/intel"
    sighting_topic = "threatbus/sighting"
    socket.setsockopt(zmq.SUBSCRIBE, intel_topic.encode())
    socket.setsockopt(zmq.SUBSCRIBE, sighting_topic.encode())

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
                inq.put(decoded)
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
