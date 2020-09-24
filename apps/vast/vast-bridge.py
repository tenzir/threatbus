#!/usr/bin/env python3

import argparse
import asyncio
import atexit
import coloredlogs
from datetime import datetime
import json
import logging
from message_mapping import (
    get_vast_intel_type,
    get_ioc,
    matcher_result_to_threatbus_sighting,
    query_result_to_threatbus_sighting,
    to_vast_ioc,
    to_vast_query,
)
from pyvast import VAST
import random
from string import ascii_lowercase as letters
from threatbus.data import Intel, IntelDecoder, Sighting, SightingEncoder, Operation
import zmq

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


async def start(
    cmd,
    vast_endpoint,
    zmq_endpoint,
    snapshot,
    retro_match,
    transform_cmd=None,
    sink=None,
):
    """
    Starts the bridge between the two given endpoints. Subscribes the
    configured VAST instance for threat intelligence (IoCs) and reports new
    intelligence to Threat Bus.
    @param cmd The vast binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running vast node
    @param zmq_endpoint The ZMQ management endpoint of Threat Bus
    @param snapshot An integer value to request n days of past intel items
    @param transform_cmd The command to use to transform Sighting context with
    @param sink Forward sighting context to this sink (subprocess) instead of
        reporting back to Threat Bus
    """
    global logger
    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    assert await vast.test_connection() is True, "Cannot connect to VAST"

    logger.debug(f"Calling Threat Bus management endpoint {zmq_endpoint}")
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
    logger.debug("Subscription successfull")
    atexit.register(unsubscribe, zmq_endpoint, topic)

    intel_queue = asyncio.Queue()
    sightings_queue = asyncio.Queue()
    report_sightings_task = asyncio.create_task(
        report_sightings(sub_endpoint, sightings_queue, transform_cmd, sink)
    )
    atexit.register(report_sightings_task.cancel)
    receive_intel_task = asyncio.create_task(
        receive_intel(pub_endpoint, topic, intel_queue)
    )
    atexit.register(receive_intel_task.cancel)
    match_task = asyncio.create_task(
        match_intel(cmd, vast_endpoint, intel_queue, sightings_queue, retro_match)
    )
    atexit.register(match_task.cancel)
    if not retro_match:
        live_match_vast_task = asyncio.create_task(
            live_match_vast(cmd, vast_endpoint, sightings_queue)
        )
        atexit.register(live_match_vast_task.cancel)
        await asyncio.gather(
            receive_intel_task, report_sightings_task, match_task, live_match_vast_task
        )
    else:
        await asyncio.gather(receive_intel_task, report_sightings_task, match_task)


async def receive_intel(pub_endpoint, topic, intel_queue):
    """
    Starts a zmq subscriber on the given endpoint and listens for new intel
    items on the given topic. Enqueues all received IoCs on the intel_queue.
    @param pub_endpoint A host:port string to connect to via zmq
    @param topic The topic to subscribe to get intelligence items
    @param intel_queue The queue to put arriving IoCs into
    """
    global logger
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
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue
            await intel_queue.put(msg)
        else:
            await asyncio.sleep(0.05)  # free event loop for other tasks


async def match_intel(cmd, vast_endpoint, intel_queue, sightings_queue, retro_match):
    """
    Reads from the intel_queue and matches all IoCs, either via VAST's
    live-matching or retro-matching.
    @param cmd The vast binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running vast node
    @param intel_queue The queue to read new IoCs from
    @param sightings_queue The queue to put new sightings into
    @param retro_match Boolean flag to use retro-matching over live-matching
    """
    global logger
    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    while True:
        msg = await intel_queue.get()
        intel = json.loads(msg, cls=IntelDecoder)
        if type(intel) is not Intel:
            logger.warn(f"Ignoring unknown message type, expected Intel: {type(intel)}")
            continue
        if intel.operation == Operation.ADD:
            if retro_match:
                query = to_vast_query(intel)
                if not query:
                    continue
                proc = await vast.export().json(query).exec()
                while not proc.stdout.at_eof():
                    line = (await proc.stdout.readline()).decode().rstrip()
                    if line:
                        sighting = query_result_to_threatbus_sighting(line, intel)
                        if not sighting:
                            logger.warn(f"Could not parse VAST query result: {line}")
                            continue
                        await sightings_queue.put(sighting)
                logger.debug(f"Finished retro-matching for intel: {intel}")
            else:
                ioc = to_vast_ioc(intel)
                if not ioc:
                    logger.warn(
                        f"Unable to convert Intel to VAST compatible IoC: {intel}"
                    )
                    continue
                proc = await vast.import_().json(type="intel.indicator").exec(stdin=ioc)
                await proc.wait()
                logger.debug(f"Ingested intel for live matching: {intel}")
        elif intel.operation == Operation.REMOVE:
            if retro_match:
                continue
            intel_type = get_vast_intel_type(intel)
            ioc = get_ioc(intel)
            if not ioc or not intel_type:
                logger.error(
                    f"Cannot remove intel with missing intel_type or indicator: {intel}"
                )
                continue
            global matcher_name
            await vast.matcher().ioc_remove(matcher_name, ioc, intel_type).exec()
            logger.debug(f"Removed indicator {intel}")
        else:
            logger.warning(f"Unsupported operation for indicator: {intel}")
        intel_queue.task_done()


async def live_match_vast(cmd, vast_endpoint, sightings_queue):
    """
    Starts a VAST matcher. Enqueues all matches from VAST to the
    sightings_queue.
    @param cmd The VAST binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running VAST node
    @param sightings_queue The queue to put new sightings into
    """
    global logger, matcher_name
    vast = VAST(binary=cmd, endpoint=vast_endpoint)
    matcher_name = "threatbus-" + "".join(random.choice(letters) for i in range(10))
    proc = await vast.matcher().start(name=matcher_name).exec()
    while True:
        data = await proc.stdout.readline()
        if not data:
            if not await vast.test_connection():
                logger.error("Lost connection to VAST, cannot live-match.")
                # TODO reconnect
            continue
        vast_sighting = data.decode("utf-8").rstrip()
        sighting = matcher_result_to_threatbus_sighting(vast_sighting)
        if not sighting:
            logger.warn(f"Cannot parse sighting-output from VAST: {data}", e)
            continue
        await sightings_queue.put(sighting)


async def invoke_cmd_for_context(cmd, context, ioc="%ioc"):
    """
    Invoke a command as subprocess for the given context. The command string is
    treated as template string and occurences of "%ioc" are replaced with the
    actually matched IoC.
    Returns stdout from the invoked command.
    @param cmd The command, including flags, to invoke as subprocess. cmd is
        treated as template string and occurrences of '%ioc' are replaced with
        the actually matched IoC.
    @param context The context (python dict) to forward as JSON
    @param ioc The value to replace '%ioc' with in the `cmd` string
    """
    if not ioc:
        ioc = "%ioc"
    cmd = cmd.replace("%ioc", ioc)
    proc = await asyncio.create_subprocess_exec(
        *cmd.split(" "),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE,
    )
    proc.stdin.write(json.dumps(context).encode())
    await proc.stdin.drain()
    proc.stdin.close()
    stdout, stderr = await proc.communicate()
    if stderr:
        logger.error(f"Error while transforming sighting context: {stderr}")
    return stdout


async def report_sightings(
    sub_endpoint, sightings_queue, transform_cmd=None, sink=None
):
    """
    Starts a ZeroMQ publisher on the given endpoint and publishes sightings from
    the sightings_queue.
    @param sub_endpoint A host:port string to connect to via ZeroMQ
    @param sightings_queue The queue to receive sightings from
    @param transform_cmd The command to use to pipe sightings to. Treated
        as template string: occurrences of '%ioc' in the cmd string get replaced
        with the matched IoC.
    @param report_data If True, only report sighting.context.data instead of the
        whole sighting.
    """
    global logger
    if transform_cmd:
        logger.info(
            f"Using '{transform_cmd}' to transform every sighting's context before sending"
        )
    if sink:
        logger.info(f"Forwarding sightings to sink '{sink}'")
    else:
        socket = zmq.Context().socket(zmq.PUB)
        socket.connect(f"tcp://{sub_endpoint}")
        topic = "threatbus/sighting"
        logger.info(f"Forwarding sightings to Threat Bus at {sub_endpoint}/{topic}")
    while True:
        sighting = await sightings_queue.get()
        if type(sighting) is not Sighting:
            logger.warn(
                f"Ignoring unknown message type, expected Sighting: {type(sighting)}"
            )
            continue
        if transform_cmd and sighting.context:
            ioc = sighting.ioc[0] if sighting.ioc else None
            context_str = await invoke_cmd_for_context(
                transform_cmd, sighting.context, ioc
            )
            try:
                context = json.loads(context_str)
                sighting.context = context
            except Exception as e:
                logger.error(
                    f"Cannot parse transformed sighting context (expecting JSON): {context_str}",
                    e,
                )
                continue
        if sink:
            if sink.lower() == "stdout":
                print(json.dumps(sighting.context))
            else:
                await invoke_cmd_for_context(sink, sighting.context)
        else:
            socket.send_string(f"{topic} {json.dumps(sighting, cls=SightingEncoder)}")
        sightings_queue.task_done()
        logger.debug(f"Reported sighting: {sighting}")


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
        type=int,
        help="Request intelligence snapshot for past n days",
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        dest="log_level",
        default="info",
        help="Loglevel to use for the bridge",
    )
    parser.add_argument(
        "--retro-match",
        dest="retro_match",
        action="store_true",
        help="Use plain vast queries instead of live-matcher",
    )
    parser.add_argument(
        "--transform-context",
        "-T",
        dest="transform",
        default=None,
        help="Forward the context of each sighting (only the contents without the Threat Bus specific sighting structure) via a UNIX pipe. This option takes a command line string to use and invokes it as direct subprocess without shell / globbing support. Note: Treated as template string. Occurrences of '%%ioc' get replaced with the matched IoC.",
    )
    parser.add_argument(
        "--sink",
        "-S",
        dest="sink",
        default=None,
        help="If sink is specified, sightings are not reported back to Threat Bus. Instead, the context of a sighting (only the contents without the Threat Bus specific sighting structure) is forwarded to the specified sink via a UNIX pipe. This option takes a command line string to use and invokes it as direct subprocess without shell / globbing support.",
    )

    args = parser.parse_args()

    setup_logging(args.log_level)
    asyncio.run(
        start(
            args.binary,
            args.vast,
            args.threatbus,
            args.snapshot,
            args.retro_match,
            args.transform,
            args.sink,
        )
    )


if __name__ == "__main__":
    main()
