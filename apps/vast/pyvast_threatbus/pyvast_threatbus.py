#!/usr/bin/env python3

import argparse
import asyncio
import atexit
import coloredlogs
import confuse
import json
import logging
from .message_mapping import (
    get_vast_intel_type,
    get_ioc,
    matcher_result_to_threatbus_sighting,
    query_result_to_threatbus_sighting,
    to_vast_ioc,
    to_vast_query,
)
from pyvast import VAST
import random
from shlex import split as lexical_split
from string import ascii_lowercase as letters
from threatbus.data import Intel, IntelDecoder, Sighting, SightingEncoder, Operation
import zmq

logger = logging.getLogger(__name__)
matcher_name = None
# list of all running async tasks of the bridge
async_tasks = []
# the p2p topic that was given to the vast-bridge upon successful subscription
p2p_topic = None
max_open_tasks = None


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


def validate_config(config: confuse.Subview):
    assert config, "config must not be None"
    config["vast"].get(str)
    config["vast_binary"].get(str)
    config["threatbus"].get(str)
    config["snapshot"].get(int)
    config["loglevel"].get(str)
    config["retro_match"].get(bool)
    config["retro_match_max_events"].get(int)
    config["unflatten"].get(bool)
    config["max_background_tasks"].get(int)

    # fallback values for the optional arguments
    config["transform_context"].add(None)
    config["sink"].add(None)


def cancel_async_tasks():
    """
    Cancels all async tasks.
    """
    global async_tasks
    for task in async_tasks:
        task.cancel()
        del task
    async_tasks = []


async def start(
    vast_binary: str,
    vast_endpoint: str,
    zmq_endpoint: str,
    snapshot: int,
    retro_match: bool,
    retro_match_max_events: int,
    unflatten: bool,
    max_open_files: int,
    transform_cmd: str = None,
    sink: str = None,
):
    """
    Starts the app between the two given endpoints. Subscribes the configured
    VAST instance for threat intelligence (IoCs) and reports new intelligence to
    Threat Bus.
    @param cmd The vast binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running VAST node ('host:port')
    @param zmq_endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param snapshot An integer value to request n days of past intel items
    @param retro_match Boolean flag to use retro-matching over live-matching
    @param retro_match_max_events Max amount of retro match results
    @param unflatten Boolean flag to unflatten JSON when received from VAST
    @param max_open_files The maximum number of concurrent background tasks for VAST queries.
    @param transform_cmd The command to use to transform Sighting context with
    @param sink Forward sighting context to this sink (subprocess) instead of
        reporting back to Threat Bus
    """
    global logger, async_tasks, p2p_topic, max_open_tasks
    # needs to be created inside the same eventloop where it is used
    max_open_tasks = asyncio.Semaphore(max_open_files)
    vast = VAST(binary=vast_binary, endpoint=vast_endpoint, logger=logger)
    assert await vast.test_connection() is True, "Cannot connect to VAST"

    logger.debug(f"Calling Threat Bus management endpoint {zmq_endpoint}")
    reply = subscribe(zmq_endpoint, "threatbus/intel", snapshot)
    if not reply_is_success(reply):
        logger.error("Subscription failed")
        return
    pub_endpoint = reply.get("pub_endpoint", None)
    sub_endpoint = reply.get("sub_endpoint", None)
    topic = reply.get("topic", None)
    if not pub_endpoint or not sub_endpoint or not topic:
        logger.error("Subscription failed")
        return
    logger.info(f"Subscription successful. New p2p_topic: {topic}")
    if p2p_topic:
        # The 'start' function is called as result of a restart
        # Unsubscribe the old topic as soon as we get a working connection
        logger.info("Cleaning up old p2p_topic subscription ...")
        unsubscribe(zmq_endpoint, p2p_topic)
        atexit.unregister(unsubscribe)
    p2p_topic = topic
    atexit.register(unsubscribe, zmq_endpoint, topic)

    async_tasks.append(
        asyncio.create_task(heartbeat(zmq_endpoint, p2p_topic, interval=5))
    )

    intel_queue = asyncio.Queue()
    sightings_queue = asyncio.Queue()
    async_tasks.append(
        asyncio.create_task(
            report_sightings(sub_endpoint, sightings_queue, transform_cmd, sink)
        )
    )

    async_tasks.append(
        asyncio.create_task(receive(pub_endpoint, p2p_topic, intel_queue))
    )

    async_tasks.append(
        asyncio.create_task(
            match_intel(
                vast_binary,
                vast_endpoint,
                intel_queue,
                sightings_queue,
                retro_match,
                retro_match_max_events,
                unflatten,
            )
        )
    )

    if not retro_match:
        async_tasks.append(
            asyncio.create_task(
                live_match_vast(vast_binary, vast_endpoint, sightings_queue)
            )
        )

    atexit.register(cancel_async_tasks)
    return await asyncio.gather(*async_tasks)


async def receive(pub_endpoint: str, topic: str, intel_queue: asyncio.Queue):
    """
    Starts a zmq subscriber on the given endpoint and listens for new messages
    that are published on the given topic (zmq prefix matching). Depending on
    the topic suffix, Intel items (IoCs) are enqueued to the intel_queue.
    @param pub_endpoint A host:port string to connect to via zmq
    @param topic The topic prefix to subscribe to intelligence items
    @param intel_queue The queue to put arriving IoCs into
    """
    global logger
    socket = zmq.Context().socket(zmq.SUB)
    socket.connect(f"tcp://{pub_endpoint}")
    socket.setsockopt(zmq.SUBSCRIBE, topic.encode())
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    logger.info(f"Receiving via ZMQ on topic {pub_endpoint}/{topic}")
    while True:
        socks = dict(
            poller.poll(timeout=100)
        )  # note that smaller timeouts may increase CPU load
        if socket in socks and socks[socket] == zmq.POLLIN:
            try:
                topic, msg = socket.recv().decode().split(" ", 1)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue
            # the topic is suffixed with the message type
            if not topic.endswith("intel"):
                # pyvast-threatbus is not (yet) interested in Sightings or SnapshotRequests
                logger.debug(f"Skipping unsupported message: {msg}")
                continue
            await intel_queue.put(msg)
        else:
            await asyncio.sleep(0.05)  # free event loop for other tasks


async def retro_match_vast(
    vast_binary,
    vast_endpoint,
    retro_match_max_events,
    intel,
    sightings_queue,
    unflatten,
):
    """
    Turns the given intel into a valid VAST query and forwards all all query
    results (sightings) to the sightings_queue.
    @param vast_binary The vast binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running vast node ('host:port')
    @param retro_match_max_events  Max amount of retro match results
    @param intel The IoC to query VAST for
    @param sightings_queue The queue to put new sightings into
    @param unflatten Boolean flag to unflatten JSON when received from VAST
    """
    query = to_vast_query(intel)
    if not query:
        return
    global logger, max_open_tasks
    async with max_open_tasks:
        vast = VAST(binary=vast_binary, endpoint=vast_endpoint, logger=logger)
        proc = await vast.export(max_events=retro_match_max_events).json(query).exec()
        reported = 0
        while not proc.stdout.at_eof():
            line = (await proc.stdout.readline()).decode().rstrip()
            if line:
                sighting = query_result_to_threatbus_sighting(line, intel, unflatten)
                if not sighting:
                    logger.error(f"Could not parse VAST query result: {line}")
                    continue
                reported += 1
                await sightings_queue.put(sighting)
        logger.debug(f"Retro-matched {reported} sighting(s) for intel: {intel}")


async def ingest_vast_ioc(vast_binary, vast_endpoint, intel):
    """
    Ingests the given intel as IoC into a VAST matcher.
    @param vast_binary The vast binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running vast node ('host:port')
    @param intel The IoC to query VAST for
    """
    global logger
    ioc = to_vast_ioc(intel)
    if not ioc:
        logger.error(f"Unable to convert Intel to VAST compatible IoC: {intel}")
        return
    vast = VAST(binary=vast_binary, endpoint=vast_endpoint, logger=logger)
    proc = await vast.import_().json(type="intel.indicator").exec(stdin=ioc)
    await proc.wait()
    logger.debug(f"Ingested intel for live matching: {intel}")


async def remove_vast_ioc(vast_binary, vast_endpoint, intel):
    """
    Removes the given intel as IoC from a VAST matcher.
    @param vast_binary The vast binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running vast node ('host:port')
    @param intel The IoC to query VAST for
    """
    global logger, matcher_name
    intel_type = get_vast_intel_type(intel)
    ioc = get_ioc(intel)
    if not ioc or not intel_type:
        logger.error(
            f"Cannot remove intel with missing intel_type or indicator: {intel}"
        )
        return
    vast = VAST(binary=vast_binary, endpoint=vast_endpoint, logger=logger)
    await vast.matcher().ioc_remove(matcher_name, ioc, intel_type).exec()
    logger.debug(f"Removed indicator {intel}")


async def match_intel(
    vast_binary: str,
    vast_endpoint: str,
    intel_queue: asyncio.Queue,
    sightings_queue: asyncio.Queue,
    retro_match: bool,
    retro_match_max_events: int,
    unflatten: bool,
):
    """
    Reads from the intel_queue and matches all IoCs, either via VAST's
    live-matching or retro-matching.
    @param vast_binary The vast binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running vast node ('host:port')
    @param intel_queue The queue to read new IoCs from
    @param sightings_queue The queue to put new sightings into
    @param retro_match Boolean flag to use retro-matching over live-matching
    @param retro_match_max_events  Max amount of retro match results
    @param unflatten Boolean flag to unflatten JSON when received from VAST
    """
    global logger, open_tasks
    while True:
        msg = await intel_queue.get()
        try:
            intel = json.loads(msg, cls=IntelDecoder)
        except Exception as e:
            logger.warning(f"Failed to decode intel item {msg}: {e}")
            continue
        if type(intel) is not Intel:
            logger.warning(
                f"Ignoring unknown message type, expected Intel: {type(intel)}"
            )
            continue
        if intel.operation == Operation.ADD:
            if retro_match:
                asyncio.create_task(
                    retro_match_vast(
                        vast_binary,
                        vast_endpoint,
                        retro_match_max_events,
                        intel,
                        sightings_queue,
                        unflatten,
                    )
                )
            else:
                asyncio.create_task(ingest_vast_ioc(vast_binary, vast_endpoint, intel))
        elif intel.operation == Operation.REMOVE:
            if retro_match:
                continue
            asyncio.create_task(remove_vast_ioc(vast_binary, vast_endpoint, intel))
        else:
            logger.warning(f"Unsupported operation for indicator: {intel}")
        intel_queue.task_done()


async def live_match_vast(
    vast_binary: str, vast_endpoint: str, sightings_queue: asyncio.Queue
):
    """
    Starts a VAST matcher. Enqueues all matches from VAST to the
    sightings_queue.
    @param vast_binary The VAST binary command to use with PyVAST
    @param vast_endpoint The endpoint of a running VAST node
    @param sightings_queue The queue to put new sightings into
    @param retro_match Boolean flag to use retro-matching over live-matching
    """
    global logger, matcher_name
    vast = VAST(binary=vast_binary, endpoint=vast_endpoint, logger=logger)
    matcher_name = "threatbus-" + "".join(random.choice(letters) for i in range(10))
    proc = await vast.matcher().start(name=matcher_name).exec()
    while True:
        data = await proc.stdout.readline()
        if not data:
            if not await vast.test_connection():
                logger.error("Lost connection to VAST, cannot live-match")
                # TODO reconnect
            continue
        vast_sighting = data.decode("utf-8").rstrip()
        sighting = matcher_result_to_threatbus_sighting(vast_sighting)
        if not sighting:
            logger.error(f"Cannot parse sighting-output from VAST: {vast_sighting}")
            continue
        await sightings_queue.put(sighting)


async def invoke_cmd_for_context(cmd: str, context: dict, ioc: str = "%ioc"):
    """
    Invoke a command as subprocess for the given context. The command string is
    treated as template string and occurences of "%ioc" are replaced with the
    actually matched IoC.
    Returns stdout from the invoked command.
    @param cmd The command, including flags, to invoke as subprocess. cmd is
        treated as template string and occurrences of '%ioc' are replaced with
        the actually matched IoC.
    @param context The context to forward as JSON
    @param ioc The value to replace '%ioc' with in the `cmd` string
    """
    if not ioc:
        ioc = "%ioc"
    cmd = cmd.replace("%ioc", ioc)
    proc = await asyncio.create_subprocess_exec(
        *lexical_split(cmd),
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
    sub_endpoint: str,
    sightings_queue: asyncio.Queue,
    transform_cmd: str = None,
    sink: str = None,
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
            logger.warning(
                f"Ignoring unknown message type, expected Sighting: {type(sighting)}"
            )
            continue
        if transform_cmd and sighting.context:
            ioc = sighting.ioc
            if sighting.ioc and type(sighting.ioc) is tuple:
                ioc = sighting.ioc[0]  # use first value of tuple
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


def send_manage_message(endpoint: str, action: dict, timeout: int = 5):
    """
    Sends a 'management' message, following the threatbus-zmq-app protocol to
    either subscribe or unsubscribe this application to/from Threat Bus.
    @param endpoint A host:port string to connect to via ZeroMQ
    @param action The message to send as JSON
    @param timeout The period after which the connection attempt is aborted
    """
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(f"tcp://{endpoint}")
    socket.send_json(action)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    reply = None
    if poller.poll(timeout * 1000):
        reply = socket.recv_json()
    socket.close()
    context.term()
    return reply


def reply_is_success(reply: dict):
    """
    Predicate to check if `reply` is a dict and contains the key-value pair
    "status" = "success"
    @param reply A python dict
    @return True if the dict contains "status" = "success"
    """
    return (
        reply
        and type(reply) is dict
        and reply.get("status", None)
        and reply["status"] == "success"
    )


def subscribe(endpoint: str, topic: str, snapshot: int, timeout: int = 5):
    """
    Subscribes this app to the Threat Bus for the given topic. Requests an
    optional snapshot of past intelligence data.
    @param endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param topic The topic to subscribe to
    @param snapshot An integer value to request n days of past intel items
    @param timeout The period after which the connection attempt is aborted
    """
    global logger
    logger.info(f"Subscribing to topic '{topic}'...")
    action = {"action": "subscribe", "topic": topic, "snapshot": snapshot}
    return send_manage_message(endpoint, action, timeout)


def unsubscribe(endpoint: str, topic: str, timeout: int = 5):
    """
    Unsubscribes this app from Threat Bus for the given topic.
    @param endpoint The ZMQ management endpoint of Threat Bus
    @param topic The topic to unsubscribe from
    @param timeout The period after which the connection attempt is aborted
    """
    global logger
    logger.info(f"Unsubscribing from topic '{topic}' ...")
    action = {"action": "unsubscribe", "topic": topic}
    reply = send_manage_message(endpoint, action, timeout)
    if not reply_is_success(reply):
        logger.warning("Unsubscription failed")
        return
    logger.info("Unsubscription successful")


async def heartbeat(endpoint: str, p2p_topic: str, interval: int = 5):
    """
    Sends heartbeats to Threat Bus periodically to check if the given p2p_topic
    is still valid at the Threat Bus host. Cancels all async tasks of this app
    when the heartbeat fails and stops the heartbeat.
    @param endpoint The ZMQ management endpoint of Threat Bus
    @param p2p_topic The topic string to include in the heartbeat
    @param timeout The period after which the connection attempt is aborted
    """
    global logger, async_tasks
    action = {"action": "heartbeat", "topic": p2p_topic}
    while True:
        reply = send_manage_message(endpoint, action, interval)
        if not reply_is_success(reply):
            logger.error("Subscription with Threat Bus host became invalid")
            cancel_async_tasks()
            return
        await asyncio.sleep(interval)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="Path to a configuration file")
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
        dest="vast_binary",
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
        dest="loglevel",
        default="info",
        help="Loglevel to use",
    )
    parser.add_argument(
        "--retro-match",
        dest="retro_match",
        action="store_true",
        help="Use plain vast queries instead of live-matcher",
    )
    parser.add_argument(
        "--unflatten",
        dest="unflatten",
        action="store_true",
        help="Only applicable when --retro-match is used. Unflatten the JSON results from VAST. The unflattening is applied immediately after retrieving the results from VAST, i.e., unflatten is applied before all further processing steps like --transform-context, --sink, or reporting back to Threat Bus.",
    )
    parser.add_argument(
        "--retro-match-max-events",
        dest="retro_match_max_events",
        default=0,
        type=int,
        help="Use this options to fine-tune '--retro-match'. The app passes this option to VAST to at most return the configured number of sightings per IoC.",
    )
    parser.add_argument(
        "--transform-context",
        "-T",
        dest="transform_context",
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
    parser.add_argument(
        "--max-background-tasks",
        "-U",
        dest="max-background-tasks",
        default=100,
        type=int,
        help="Controls the maximum number of concurrent background tasks for VAST queries. Default is 100.",
    )
    args = parser.parse_args()

    config = confuse.Configuration("pyvast-threatbus")
    config.set_args(args)
    if args.config:
        config.set_file(args.config)

    try:
        validate_config(config)
    except Exception as e:
        raise ValueError(f"Invalid config: {e}")

    setup_logging(config["loglevel"].get(str))
    while True:
        try:
            asyncio.run(
                start(
                    config["vast_binary"].get(),
                    config["vast"].get(),
                    config["threatbus"].get(),
                    config["snapshot"].get(),
                    config["retro_match"].get(),
                    config["retro_match_max_events"].get(),
                    config["unflatten"].get(),
                    config["max_background_tasks"].get(),
                    config["transform_context"].get(),
                    config["sink"].get(),
                )
            )
        except asyncio.CancelledError:
            logger.info("Restarting pyvast-threatbus ...")


if __name__ == "__main__":
    main()
