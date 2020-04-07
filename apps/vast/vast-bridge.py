#!/usr/bin/env python3

import argparse
import asyncio
import atexit
import logging
import json
import zmq

from pyvast import VAST

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")


async def start(cmd, vast_endpoint, management_endpoint, snapshot):
    """
    Starts the bridge between the two given endpoints. Subscribes the configured
    VAST instance for threat intelligence (IoCs) and reports new intelligence to
    Threat Bus.
    """

    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    assert await vast.test_connection() is True, "Cannot connect to VAST"

    # stdout, _ = await vast.export().json('#type == "intel.sighting"').exec()
    logger.info(f"Subscribing to Threat Bus {management_endpoint}")
    reply = subscribe(management_endpoint, "threatbus/intel", snapshot)
    if not reply or not isinstance(reply, dict):
        logger.error("Subsription unsuccessful")
        exit(1)
    pubsub_endpoint, topic = reply.get("endpoint", None), reply.get("topic", None)
    if not pubsub_endpoint or not topic:
        logger.error("Unparsable subscription reply")
        exit(1)
    logger.info(f"Subscription successfull")
    atexit.register(unsubscribe, management_endpoint, topic)
    await receive(vast, pubsub_endpoint, topic)


async def receive(vast, pubsub_endpoint, topic):
    """
        Starts a zmq subscriber on the given endpoint and listens for the
        desired topic.
        @param vast A pyvast instance to be used for interaction with vast
        @param pubsub_endpoint A host:port string to connect to via zmq
        @param topic The topic to subscribe to
    """

    socket = zmq.Context().socket(zmq.SUB)
    socket.connect(f"tcp://{pubsub_endpoint}")
    socket.setsockopt(zmq.SUBSCRIBE, topic.encode())
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    logger.info(
        f"Subscribed to continuous pub-sub broker intel broker on {pubsub_endpoint} - {topic}"
    )
    while True:
        socks = dict(poller.poll(timeout=None))
        if socket in socks and socks[socket] == zmq.POLLIN:
            try:
                _, msg = socket.recv().decode().split(" ", 1)
                intel = json.loads(msg)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue
            await vast.import_().json(type="intel.pulsedive").exec(
                stdin=json.dumps(intel)
            )


def subscribe(endpoint, topic, snapshot):
    """
        Subscribes the vast-bridge to the Threat Bus for the given topic.
        Requests an optional snapshot of past intelligence data.
    """
    subscription = {"action": "subscribe", "topic": topic, "snapshot": snapshot}
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(f"tcp://{endpoint}")
    socket.send_json(subscription)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    reply = None
    if poller.poll(5 * 1000):  # timeout
        reply = socket.recv_json()
    socket.close()
    context.term()
    return reply


def unsubscribe(endpoint, topic):
    """
        Unsubscribes the vast-bridge from Threat Bus for the given topic.
    """
    logger.info("Unsubscribing...")
    unsub = {"action": "unsubscribe", "topic": topic}
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(f"tcp://{endpoint}")
    socket.send_json(unsub)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    reply = "Unsuccessful"
    if poller.poll(5 * 1000):  # timeout
        reply = socket.recv_string()
    socket.close()
    context.term()
    logger.info(f"Unsubscription: {reply}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--vast",
        "-v",
        dest="vast",
        default="localhost:42000",
        help="Endpoint of a running VAST node",
    )
    parser.add_argument(
        "--vast-binary",
        "-b",
        dest="binary",
        default="vast",
        help="The vast command to use (either absolte path or a command available in $PATH)",
    )
    parser.add_argument(
        "--threatbus",
        "-t",
        dest="threatbus",
        default="localhost:13370",
        help="Management endpoint of a VAST Threat Bus node",
    )
    parser.add_argument(
        "--snapshot",
        "-s",
        dest="snapshot",
        default=0,
        help="Request intelligence snapshot for past n days",
    )
    args = parser.parse_args()
    asyncio.run(start(args.binary, args.vast, args.threatbus, args.snapshot))


if __name__ == "__main__":
    main()
