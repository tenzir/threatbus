#!/usr/bin/env python3

import argparse
import asyncio
import atexit
from dynaconf import Dynaconf, Validator
from dynaconf.base import Settings
from dynaconf.utils.boxing import DynaBox
import json
import logging
from .message_mapping import map_bundle_to_sightings
import signal
from stix2 import parse, Indicator, Sighting
from stix_shifter.stix_translation import stix_translation
from stix_shifter.stix_transmission import stix_transmission
import sys
from threatbus.logger import setup as setup_logging_threatbus
import warnings
import zmq

# Ignore warnings about SSL configuration in the user configs.
warnings.filterwarnings("ignore")

logger_name = "stix-shifter-threatbus"
logger = logging.getLogger(logger_name)
# List of all running async tasks of the bridge.
async_tasks = []
# The p2p topic sent back by Threat Bus upon successful subscription.
p2p_topic = None
# Boolean flag indicating that the user has issued a SIGNAL (e.g., SIGTERM).
user_exit = False

### --------------------------- Application helpers ---------------------------


def setup_logging_with_config(config: DynaBox):
    """
    Sets up the global logger as configured in the `config` object.
    @param config The user-defined logging configuration
    """
    global logger
    logger = setup_logging_threatbus(config, logger_name)
    logging.getLogger("stix-shifter-utils").propagate = False


def validate_config(config: Settings):
    """
    Validates the given Dynaconf object. Throws if the config is invalid.
    """
    validators = [
        Validator("logging.console", is_type_of=bool, required=True, eq=True)
        | Validator("logging.file", is_type_of=bool, required=True, eq=True),
        Validator(
            "logging.console_verbosity",
            is_in=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            required=True,
            when=Validator("logging.console", eq=True),
        ),
        Validator(
            "logging.file_verbosity",
            is_in=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            required=True,
            when=Validator("logging.file", eq=True),
        ),
        Validator(
            "logging.filename", required=True, when=Validator("logging.file", eq=True)
        ),
        Validator("threatbus", required=True),
        Validator("snapshot", is_type_of=int, required=True),
        Validator("modules", is_type_of=dict, required=True),
    ]

    if "modules" in config:
        for mod in config.modules.keys():
            validators.append(
                Validator(f"modules.{mod}.max_results", is_type_of=int, required=True)
            )
            validators.append(
                Validator(f"modules.{mod}.connection", is_type_of=dict, required=True)
            )
            validators.append(
                Validator(f"modules.{mod}.data_source", is_type_of=dict, required=True)
            )
            validators.append(
                Validator(f"modules.{mod}.data_source.type", required=True)
            )
            validators.append(
                Validator(f"modules.{mod}.data_source.name", required=True)
            )
            validators.append(Validator(f"modules.{mod}.data_source.id", required=True))
            validators.append(
                Validator(f"modules.{mod}.transmission", is_type_of=dict, default={})
            )  # default to empty config
            validators.append(
                Validator(f"modules.{mod}.translation", is_type_of=dict, default={})
            )  # default to empty config

    config.validators.register(*validators)
    config.validators.validate()


async def cancel_async_tasks():
    """
    Cancels all async tasks.
    """
    global async_tasks
    for task in async_tasks:
        if task is not asyncio.current_task():
            task.cancel()
            del task
    async_tasks = []
    return await asyncio.gather(*async_tasks)


async def stop_signal():
    """
    Implements Python's asyncio eventloop signal handler
    https://docs.python.org/3/library/asyncio-eventloop.html
    Cancels all running tasks and exits the app.
    """
    global user_exit
    user_exit = True
    await cancel_async_tasks()


### --------------- ZeroMQ communication / management functions ---------------


def send_manage_message(endpoint: str, action: dict, timeout: int = 5):
    """
    Sends a 'management' message, following the threatbus-zmq protocol to
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
    Subscribes this app to Threat Bus for the given topic. Requests an optional
    snapshot of historical indicators.
    @param endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param topic The topic to subscribe to
    @param snapshot An integer value to request n days of historical IoC items
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
    global logger
    action = {"action": "heartbeat", "topic": p2p_topic}
    while True:
        reply = send_manage_message(endpoint, action, interval)
        if not reply_is_success(reply):
            logger.error("Subscription with Threat Bus host became invalid")
            return await cancel_async_tasks()
        await asyncio.sleep(interval)


### --------------------------- The actual app logic ---------------------------


async def start(zmq_endpoint: str, snapshot: int, modules_config: dict):
    """
    Starts the STIX-Shifter Threat Bus app.
    @param zmq_endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param snapshot An integer value to request n days of historical IoC items
    @param modules_config User-provided configuration for STIX-Shifter modules
    """
    global logger, async_tasks, p2p_topic
    # needs to be created inside the same eventloop where it is used
    logger.debug(f"Calling Threat Bus management endpoint {zmq_endpoint}")
    reply = subscribe(zmq_endpoint, "stix2/indicator", snapshot)
    if not reply_is_success(reply):
        logger.error("Subscription failed")
        return
    pub_port = reply.get("pub_port", None)
    sub_port = reply.get("sub_port", None)
    topic = reply.get("topic", None)
    if not pub_port or not sub_port or not topic:
        logger.error("Subscription failed")
        return
    zmq_host = zmq_endpoint.split(":")[0]
    pub_endpoint = f"{zmq_host}:{pub_port}"
    sub_endpoint = f"{zmq_host}:{sub_port}"

    logger.info(f"Subscription successful. New p2p_topic: {topic}")
    if p2p_topic:
        # The 'start' function is called as result of a restart
        # Unsubscribe the old topic as soon as we get a working connection
        logger.info("Cleaning up old p2p_topic subscription ...")
        unsubscribe(zmq_endpoint, p2p_topic)
        atexit.unregister(unsubscribe)
    p2p_topic = topic
    atexit.register(unsubscribe, zmq_endpoint, topic)

    # Set task exception handler.
    loop = asyncio.get_event_loop()

    def exception_handler(loop, context):
        logger.error(f"Error in async task: {context}")

    loop.set_exception_handler(exception_handler)

    # Start a heartbeat task so we notice when the Threat Bus host goes away.
    async_tasks.append(
        asyncio.create_task(heartbeat(zmq_endpoint, p2p_topic, interval=5))
    )

    # Create queues (channels) for passing indicators and sightings
    # asynchronously between the routines that make up this app.
    indicator_queue = asyncio.Queue()
    sightings_queue = asyncio.Queue()

    # Start a receive task to retrieve real-time updates from Threat Bus.
    async_tasks.append(
        asyncio.create_task(receive(pub_endpoint, p2p_topic, indicator_queue))
    )
    async_tasks.append(
        asyncio.create_task(
            process_indicators(indicator_queue, sightings_queue, modules_config)
        )
    )

    # Start a publisher task to send back sightings to Threat Bus.
    async_tasks.append(
        asyncio.create_task(report_sightings(sub_endpoint, sightings_queue))
    )

    loop = asyncio.get_event_loop()
    for s in [signal.SIGHUP, signal.SIGTERM, signal.SIGINT]:
        loop.add_signal_handler(s, lambda: asyncio.create_task(stop_signal()))
    return await asyncio.gather(*async_tasks)


async def receive(pub_endpoint: str, topic: str, indicator_queue: asyncio.Queue):
    """
    Starts a zmq subscriber on the given endpoint and listens for new messages
    that are published on the given topic (zmq prefix matching). Depending on
    the topic suffix, Indicators are enqueued to the indicator_queue.
    @param pub_endpoint A host:port string to connect to via zmq
    @param topic The topic prefix to subscribe to intelligence items
    @param indicator_queue The queue to put arriving IoCs into
    """
    global logger
    socket = zmq.Context().socket(zmq.SUB)
    socket.connect(f"tcp://{pub_endpoint}")
    socket.setsockopt(zmq.SUBSCRIBE, topic.encode())
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    logger.info(f"Receiving via ZMQ on topic {pub_endpoint}/{topic}")
    while True:
        socks = dict(poller.poll(timeout=100))  # Smaller timeouts increase CPU load
        if socket in socks and socks[socket] == zmq.POLLIN:
            try:
                topic, msg = socket.recv().decode().split(" ", 1)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue
            # The topic is suffixed with the message type. Use it for filtering
            if not topic.endswith("indicator"):
                logger.debug(f"Skipping unsupported message: {msg}")
                continue
            # Put the message into the queue for incoming intel items, so they
            # can be processed asynchronously
            await indicator_queue.put(msg)
        else:
            await asyncio.sleep(0.01)  # Free event loop for other tasks


async def process_indicators(
    indicator_queue: asyncio.Queue, sightings_queue: asyncio.Queue, modules_config: dict
):
    """
    Translates STIX-2 pattern and queries all configured modules via
    STIX-Shifter.
    @param indicator_queue The queue to read indicators from
    @param sightings_queue The queue to put sightings into
    @param modules_config User-provided configuration for STIX-Shifter modules
    """
    while True:
        msg = await indicator_queue.get()
        try:
            indicator = parse(msg, allow_custom=True)
        except Exception as e:
            logger.error(
                f"Error parsing indicator from Threat Bus. Expected STIX-2 Indicator: {msg}, {e}"
            )
            indicator_queue.task_done()
            continue
        logger.debug(
            f"Converting indicator from Threat Bus to module-specific query: {indicator}"
        )
        for module, opts in modules_config.items():
            asyncio.create_task(
                query_indicator(indicator, module, opts, sightings_queue)
            )
        indicator_queue.task_done()


async def query_indicator(
    indicator: Indicator, module: str, opts: dict, sightings_queue: asyncio.Queue
):
    """
    Translates an indicator into a module-specific query and executes it. E.g.,
    if the module is `splunk`, the indicator's pattern is first translated into
    a valid Splunk query and then executed via the Splunk REST API.
    @param indicator The indicator to translate and query
    @param module The module's name, e.g., `splunk`
    @param opts The module configuration directly taken from the user-defined
        configuration file `config.yaml` with which this app was started
    @param sightings_queue The queue to put sightings into
    """
    max_results = opts["max_results"]
    connection_opts = opts["connection"]
    transmission_opts = opts.get("transmission", {})
    translation_opts = opts.get("translation", {})
    data_source = opts["data_source"]

    ## Translate the pattern to a module-specific query.
    translation = stix_translation.StixTranslation()
    dsl = translation.translate(
        module, "query", indicator, indicator.pattern, translation_opts
    )
    if not dsl.get("queries", None):
        logger.error(
            f"Failed to translate STIX-2 indicator with ID '{indicator.id}' to query for module '{module}': {dsl}"
        )
        return
    logger.debug(f"Translated pattern to {module} query: {dsl}")

    ## Run the query against the configured endpoint for this module.
    transmission = stix_transmission.StixTransmission(
        module, connection_opts, transmission_opts
    )
    query_results = []
    for query in dsl["queries"]:
        search_result = transmission.query(query)
        if not search_result["success"]:
            logger.error(str(search_result))
            continue

        search_id = search_result["search_id"]

        if transmission.is_async():
            status = transmission.status(search_id)
            if not status.get("success", None):
                logger.error(f"Fetching query status failed for module '{module}'")
                return
            while status["progress"] < 100 and status["status"] == "RUNNING":
                status = transmission.status(search_id)
                await asyncio.sleep(0.05)
        result = transmission.results(search_id, 0, max_results)
        if result["success"]:
            # Collect all results
            query_results += result["data"]
        else:
            logger.error(f"Fetching results failed for module '{module}': {result}")

    ## Translate query_results to STIX.
    if not query_results:
        return

    stix_results = translation.translate(
        module,
        "results",
        json.dumps(data_source),
        json.dumps(query_results),
        translation_opts,
    )
    ## Parse output and report back sightings to Threat Bus
    ## The stix_results is always a self-made bundle with at least an `objects`
    ## field present. The bundle may be invalid STIX though, so we cannot simply
    ## invoke `parse()`. See this link for details on the bundle stucture:
    ## https://github.com/opencybersecurityalliance/stix-shifter/blob/3.4.5/stix_shifter_utils/stix_translation/src/json_to_stix/json_to_stix_translator.py#L12
    objs = stix_results.get("objects", None)
    if objs is None:
        logger.error(
            f"Received STIX bundle without `objects` field, cannot generate sightings: {stix_results}"
        )
        return
    for sighting in map_bundle_to_sightings(indicator, objs):
        await sightings_queue.put(sighting)


async def report_sightings(sub_endpoint: str, sightings_queue: asyncio.Queue):
    """
    Starts a ZeroMQ publisher on the given endpoint and publishes sightings from
    the sightings_queue to Threat Bus.
    @param sub_endpoint A host:port string to connect to via ZeroMQ
    @param sightings_queue The queue to receive sightings from
    """
    socket = zmq.Context().socket(zmq.PUB)
    socket.connect(f"tcp://{sub_endpoint}")
    topic = "stix2/sighting"
    logger.info(f"Forwarding sightings to Threat Bus at {sub_endpoint}/{topic}")
    while True:
        sighting = await sightings_queue.get()
        if type(sighting) is not Sighting:
            logger.warning(
                f"Ignoring unknown message type, expected Sighting: {type(sighting)}"
            )
            continue
        socket.send_string(f"{topic} {sighting.serialize()}")
        sightings_queue.task_done()
        logger.debug(f"Reported sighting: {sighting}")


def main():
    ## Default list of settings files for Dynaconf to parse.
    settings_files = ["config.yaml", "config.yml"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="path to a configuration file")
    args = parser.parse_args()
    if args.config:
        if not args.config.endswith("yaml") and not args.config.endswith("yml"):
            sys.exit("Please provide a `yaml` or `yml` configuration file.")
        ## Allow users to provide a custom config file that takes precedence.
        settings_files = [args.config]

    config = Dynaconf(
        settings_files=settings_files,
        load_dotenv=True,
        envvar_prefix="STIX_SHIFTER_THREATBUS",
    )

    try:
        validate_config(config)
    except Exception as e:
        sys.exit(ValueError(f"Invalid config: {e}"))

    setup_logging_with_config(config.logging)

    while True:
        try:
            asyncio.run(
                start(
                    config.threatbus,
                    config.snapshot,
                    config.modules,
                )
            )
        except (KeyboardInterrupt, SystemExit):
            return
        except asyncio.CancelledError:
            if user_exit:
                # Tasks were cancelled because the user stopped the app.
                return
            logger.info("Restarting stix-shifter-threatbus ...")


if __name__ == "__main__":
    main()
