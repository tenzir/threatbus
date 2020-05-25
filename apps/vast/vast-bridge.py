#!/usr/bin/env python3

import argparse
import asyncio
import atexit
import coloredlogs
import json
import logging
import random
from string import ascii_lowercase as letters
import sys
import zmq
from pyvast import VAST

logger = logging.getLogger(__name__)
matcher_name = None


def setup_logging(level):
    global logger
    log_level = logging.getLevelName(level.upper())

    fmt = "%(asctime)s %(levelname)-8s %(message)s"
    colored_formatter = coloredlogs.ColoredFormatter(fmt)

    handler = logging.StreamHandler()
    handler.setLevel(log_level)
    if logger.level > log_level or logger.level == 0:
        logger.setLevel(log_level)
    handler.setFormatter(colored_formatter)
    logger.addHandler(handler)


async def start(cmd, vast_endpoint, zmq_endpoint, snapshot):
    """
        Starts the bridge between the two given endpoints. Subscribes the
        configured VAST instance for threat intelligence (IoCs) and reports new
        intelligence to Threat Bus.
        @param cmd The vast binary command to use with PyVAST
        @param vast_endpoint The endpoint of a running vast node
        @param zmq_endpoint The ZMQ management endpoint of Threat Bus
        @param snapshot An integer value to request n days of past intel items
    """
    global logger
    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    assert await vast.test_connection() is True, "Cannot connect to VAST"

    logger.info(f"Calling Threat Bus management endpoint {zmq_endpoint}")
    reply = subscribe(zmq_endpoint, "threatbus/intel", snapshot)
    if not reply or not isinstance(reply, dict):
        logger.error("Subsription unsuccessful")
        exit(1)
    pub_endpoint = reply.get("pub_endpoint", None)
    sub_endpoint = reply.get("sub_endpoint", None)
    topic = reply.get("topic", None)
    if not pub_endpoint or not sub_endpoint or not topic:
        logger.error("Unparsable subscription reply")
        exit(1)
    logger.info(f"Subscription successfull")

    intel_task = asyncio.create_task(
        receive_intel(cmd, vast_endpoint, pub_endpoint, topic)
    )
    sighting_task = asyncio.create_task(
        report_sightings(cmd, vast_endpoint, sub_endpoint)
    )

    atexit.register(unsubscribe, zmq_endpoint, topic)
    atexit.register(intel_task.cancel)
    atexit.register(sighting_task.cancel)
    await asyncio.gather(intel_task, sighting_task)


async def receive_intel(cmd, vast_endpoint, pub_endpoint, topic):
    """
        Starts a zmq subscriber on the given endpoint and listens new intel
        items on the given topic.
        @param cmd The vast binary command to use with PyVAST
        @param vast_endpoint The endpoint of a running vast node
        @param pub_endpoint A host:port string to connect to via zmq
        @param topic The topic to subscribe to get intelligence items
    """
    global logger
    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    socket = zmq.Context().socket(zmq.SUB)
    socket.connect(f"tcp://{pub_endpoint}")
    socket.setsockopt(zmq.SUBSCRIBE, topic.encode())
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    logger.info(f"Receiving intelligence items on {pub_endpoint}/{topic}")
    while True:
        socks = dict(poller.poll(timeout=10))
        if socket in socks and socks[socket] == zmq.POLLIN:
            try:
                _, msg = socket.recv().decode().split(" ", 1)
                intel = json.loads(msg)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue
            operation = intel.get("operation", None)
            intel.pop("operation", None)
            if operation == "ADD":
                proc = (
                    await vast.import_()
                    .json(type="intel.indicator")
                    .exec(stdin=json.dumps(intel))
                )
                await proc.wait()
                logger.debug(f"Ingested intel: {intel}")
            elif operation == "REMOVE":
                global matcher_name
                ioc = intel.get("ioc", None)
                type_ = intel.get("type", None)
                if not ioc or not type_:
                    logger.error(
                        f"Cannot remove intel with missing required fields 'ioc' or 'type': {intel}"
                    )
                    continue
                await vast.matcher().ioc_remove(matcher_name, ioc, type_).exec()
                logger.debug(f"Removed indicator {intel}")
            else:
                logger.warning(f"Unsupported operation for indicator: {intel}")
        else:
            await asyncio.sleep(0.01)  # free event loop for other tasks


async def report_sightings(cmd, vast_endpoint, sub_endpoint):
    """
        Starts a ZeroMQ publisher on the given endpoint and publishes new sightings
        @param cmd The VAST binary command to use with PyVAST
        @param vast_endpoint The endpoint of a running VAST node
        @param sub_endpoint A host:port string to connect to via ZeroMQ
    """
    global logger
    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    socket = zmq.Context().socket(zmq.PUB)
    socket.connect(f"tcp://{sub_endpoint}")
    topic = "vast/sightings"
    logger.info(f"Forwarding sightings to {sub_endpoint}/{topic}")
    global matcher_name
    matcher_name = "threatbus-" + "".join(random.choice(letters) for i in range(10))
    proc = await vast.matcher().start(name=matcher_name).exec()
    while True:
        data = await proc.stdout.readline()
        if not data:
            if not await vast.test_connection():
                logger.error("Lost connection to VAST, exiting.")
                sys.exit(1)
            continue
        try:
            sighting = data.decode("utf-8").rstrip()
            json.loads(sighting)  # validate
            socket.send_string(f"{topic} {sighting}")
            logger.debug(f"Reported sighting: {sighting}")
        except Exception as e:
            logger.error(f"Cannot parse sighting-output from VAST: {data}", e)


def subscribe(endpoint, topic, snapshot, timeout=5):
    """
        Subscribes the vast-bridge to the Threat Bus for the given topic.
        Requests an optional snapshot of past intelligence data.
        @param endpoint The ZMQ management endpoint of Threat Bus
        @param topic The topic to subscribe to
        @param snapshot An integer value to request n days of past intel items
        @param timeout The period after which the connection attempt is aborted
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
    if poller.poll(timeout * 1000):
        reply = socket.recv_json()
    socket.close()
    context.term()
    return reply


def unsubscribe(endpoint, topic, timeout=5):
    """
        Unsubscribes the vast-bridge from Threat Bus for the given topic.
        @param endpoint The ZMQ management endpoint of Threat Bus
        @param topic The topic to unsubscribe from
        @param timeout The period after which the connection attempt is aborted
    """
    global logger
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
    if poller.poll(timeout * 1000):
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
    parser.add_argument(
        "--loglevel",
        "-l",
        dest="log_level",
        default="info",
        help="Loglevel to use for the bridge",
    )
    args = parser.parse_args()

    setup_logging(args.log_level)
    asyncio.run(start(args.binary, args.vast, args.threatbus, args.snapshot))


if __name__ == "__main__":
    main()
