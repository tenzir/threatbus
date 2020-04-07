#!/usr/bin/env python3

import argparse
import asyncio
import logging
import zmq
import time

from pyvast import VAST
from threatbus.data import Intel, IntelData, Operation

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")


async def start(cmd, vast_endpoint, threatbus_endpoint, snapshot):
    """
    Starts the bridge between the two given endpoints. Subscribes the configured
    VAST instance for threat intelligence (IoCs) and reports new intelligence to
    Threat Bus.
    """

    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    assert await vast.test_connection() is True, "Cannot connect to VAST"

    # stdout, _ = await vast.export().json('#type == "intel.sighting"').exec()
    logger.info(f"Subscribing to Threat Bus {threatbus_endpoint}")
    reply = await subscribe(threatbus_endpoint, "threatbus/intel", snapshot)
    if not reply or not isinstance(reply, dict):
        logger.error("Subsription unsuccessful")
        exit(1)
    endpoint, topic = reply.get("endpoint", None), reply.get("topic", None)
    if not endpoint or not topic:
        logger.error("Unparsable subscription reply")
        exit(1)
    logger.info(f"Subscription successfull")
    await receive(endpoint, topic)


async def receive(pubsub_endpoint, topic):
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
                msg = socket.recv_json()
            except Exception as e:
                logger.error(f"Error decoding message {message}: {e}")
                continue
            if msg.get("operation") != Operation.ADD:
                continue
            vast_intel = map_incoming_intel(msg)
            vast.import_().json(type="intel.pulsedive", stdin=vast_intel).exec()
            # TODO: issue query to vast export


async def subscribe(endpoint, topic, snapshot):
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
