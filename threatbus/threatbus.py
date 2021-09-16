import argparse
from datetime import timedelta
from dynaconf import Dynaconf, Validator
from dynaconf.base import Settings
from logging import Logger
import pluggy
from multiprocessing import JoinableQueue
from queue import Empty
import signal
import sys
from threatbus import appspecs, backbonespecs, logger, stoppable_worker
from threatbus.data import MessageType, SnapshotRequest, SnapshotEnvelope
from threading import Lock
from uuid import uuid4

if sys.version_info >= (3, 8):
    from importlib import metadata as importlib_metadata
else:
    import importlib_metadata


class ThreatBus(stoppable_worker.StoppableWorker):
    def __init__(
        self,
        backbones: pluggy._hooks._HookRelay,
        apps: pluggy._hooks._HookRelay,
        logger: Logger,
        config: Settings,
    ):
        super(ThreatBus, self).__init__()
        self.backbones = backbones
        self.apps = apps
        self.config = config
        self.logger = logger
        self.inq = JoinableQueue()  # fan-in everything, provisioned by backbone
        self.snapshot_q = JoinableQueue()
        self.lock = Lock()
        self.snapshots = dict()

    def handle_snapshots(self):
        """
        Waits to handle snapshot requests or envelopes. Forwards new requests to
        all implementing app plugins. Forwards envelopes to the requesting app
        or discards them accordingly.
        """
        while self._running():
            try:
                msg = self.snapshot_q.get(block=True, timeout=1)
            except Empty:
                continue
            if type(msg) is SnapshotRequest:
                self.logger.debug(f"Received SnapshotRequest: {msg}")
                self.apps.snapshot(snapshot_request=msg, result_q=self.inq)
            elif type(msg) is SnapshotEnvelope and msg.snapshot_id in self.snapshots:
                self.logger.debug(f"Received SnapshotEnvelope: {msg}")
                self.snapshots[msg.snapshot_id].put(msg.body)
            else:
                self.logger.warn(
                    f"Received message with unknown type on snapshot topic: {msg}"
                )
            self.snapshot_q.task_done()

    def request_snapshot(
        self, topic: str, dst_q: JoinableQueue, snapshot_id: str, time_delta: timedelta
    ):
        """
        Create a new SnapshotRequest and push it to the inq, so that the
        backbones can provision it.
        @param topic The topic for which the snapshot is requested
        @param dst_q A queue that should be used to forward all snapshot data to
        @param snapshot_id The UUID of the requested snapshot
        @param time_delta A timedelta object to mark the snapshot size
        """
        # Threat Bus follows a hierarchical pub-sub structure. Subscriptions
        # to a prefix, must hence result in a snapshot for all message-types
        # that are routed via that prefix. E.g., requesting a snapshot for
        # 'stix2' should result in both Sightings and Indicators.
        message_types = []
        if topic == "stix2" or topic == "stix2/":
            message_types = [MessageType.INDICATOR, MessageType.SIGHTING]
        elif topic.endswith("sighting"):
            message_types.append(MessageType.SIGHTING)
        elif topic.endswith("indicator"):
            message_types.append(MessageType.INDICATOR)
        for mt in message_types:
            self.logger.info(
                f"Requesting snapshot from all plugins for message type {mt.name} and time delta {time_delta}"
            )
            self.snapshots[snapshot_id] = dst_q  # store queue of requester
            req = SnapshotRequest(mt, snapshot_id, time_delta)

            self.inq.put(req)

    def subscribe(self, topic: str, q: JoinableQueue, time_delta: timedelta = None):
        """
        Accepts a new subscription for a given topic and queue pointer.
        Forwards that subscription to all managed backbones.
        @param topic Subscribe to this topic
        @param q A queue object to forward all messages for the given topics
        @param time_delta A timedelta object to mark the snapshot size
        @return Returns the UUID for the requested snapshot, or None in case no
            snapshot was requested.
        """
        assert isinstance(topic, str), "topic must be string"
        self.backbones.subscribe(topic=topic, q=q)
        if not time_delta:
            return None
        snapshot_id = str(uuid4())
        self.request_snapshot(topic, q, snapshot_id, time_delta)
        return snapshot_id

    def unsubscribe(self, topic: str, q: JoinableQueue):
        """
        Removes subscription for a given topic and queue pointer from all
        managed backbones.
        """
        assert isinstance(topic, str), "topic must be string"
        self.backbones.unsubscribe(topic=topic, q=q)

    def stop(self):
        """
        Stops all running threads and Threat Bus
        """
        self.logger.info("Stopping plugins...")
        self.backbones.stop()
        self.apps.stop()
        self.logger.info("Stopping Threat Bus...")
        super(ThreatBus, self).stop()
        self.join()

    def stop_signal(self, signal, frame):
        """
        Implements Python's signal.signal handler.
        See https://docs.python.org/3/library/signal.html#signal.signal
        Stops all running threads and Threat Bus
        """
        self.stop()

    def run(self):
        self.logger.info("Starting plugins...")
        logging = self.config.logging
        self.backbones.run(
            config=self.config.plugins.backbones, logging=logging, inq=self.inq
        )
        self.subscribe("threatbus/snapshotrequest", self.snapshot_q)
        self.subscribe("threatbus/snapshotenvelope", self.snapshot_q)
        self.apps.run(
            config=self.config.plugins.apps,
            logging=logging,
            inq=self.inq,
            subscribe_callback=self.subscribe,
            unsubscribe_callback=self.unsubscribe,
        )
        self.handle_snapshots()


def validate_threatbus_config(config: Settings):
    """
    Validates the given Dynaconf object, potentially adding new entries for the default values.
    Throws if the config is invalid.
    """
    validators = [
        Validator("logging.console", is_type_of=bool, required=True, default=True),
        Validator("logging.file", is_type_of=bool, required=True, default=False),
        Validator(
            "logging.console_verbosity",
            is_in=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
        ),
        Validator(
            "logging.file_verbosity",
            is_in=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
        ),
        Validator(
            "logging.filename",
            required=True,
            when=Validator("logging.file", eq=True, default="threatbus.log"),
        ),
        Validator("plugins.apps", "plugins.backbones", required=True),
    ]
    config.validators.register(*validators)
    config.validators.validate()


# Logic for this function taken from pluggy.PluginManager.load_setuptools_entrypoints()
def list_installed(group):
    result = []
    for dist in list(importlib_metadata.distributions()):
        result += [ep.name for ep in dist.entry_points if ep.group == group]
    return result


def start(config: Settings):

    backbones = pluggy.PluginManager("threatbus.backbone")
    backbones.add_hookspecs(backbonespecs)

    apps = pluggy.PluginManager("threatbus.app")
    apps.add_hookspecs(appspecs)

    tb_logger = logger.setup(config.logging, "threatbus")

    installed_apps = set(list_installed("threatbus.app"))
    configured_apps = set(config.plugins.apps.keys())
    for app in configured_apps:
        apps.load_setuptools_entrypoints("threatbus.app", app)

    installed_backbones = set(list_installed("threatbus.backbone"))
    configured_backbones = set(config.plugins.backbones.keys())
    for backbone in configured_backbones:
        backbones.load_setuptools_entrypoints("threatbus.backbone", backbone)

    ## Notify user about configuration mismatches between installed and
    ## configured plugins.
    for unwanted_app in installed_apps - configured_apps:
        tb_logger.info(f"Ignoring installed, but unconfigured app '{unwanted_app}'")

    for unwanted_backbones in installed_backbones - configured_backbones:
        tb_logger.info(
            f"Ignoring installed, but unconfigured backbones '{unwanted_backbones}'"
        )
    for unconfigured_app in (configured_apps - installed_apps).union(
        configured_backbones - installed_backbones
    ):
        tb_logger.warn(
            f"Found configuration for '{unconfigured_app}' but no corresponding plugin is installed."
        )

    ## Validate all plugins that are both installed and configured
    for validators in apps.hook.config_validators():
        config.validators.register(*validators)
    for validators in backbones.hook.config_validators():
        config.validators.register(*validators)
    try:
        config.validators.validate()
    except Exception as e:
        sys.exit(f"Invalid config: {e}")

    bus_thread = ThreatBus(backbones.hook, apps.hook, tb_logger, config)
    signal.signal(signal.SIGINT, bus_thread.stop_signal)
    bus_thread.start()
    return bus_thread


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
        envvar_prefix="THREATBUS",
    )

    try:
        validate_threatbus_config(config)
    except Exception as e:
        sys.exit(f"Invalid config: {e}")

    start(config)


if __name__ == "__main__":
    main()
