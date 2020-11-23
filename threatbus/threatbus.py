import argparse
import confuse
from datetime import timedelta
from logging import Logger
import pluggy
from multiprocessing import JoinableQueue
from queue import Empty
import signal
from threatbus import appspecs, backbonespecs, logger, stoppable_worker
from threatbus.data import MessageType, SnapshotRequest, SnapshotEnvelope
from threading import Lock
from uuid import uuid4


class ThreatBus(stoppable_worker.StoppableWorker):
    def __init__(
        self,
        backbones: pluggy.hooks._HookRelay,
        apps: pluggy.hooks._HookRelay,
        logger: Logger,
        config: confuse.Subview,
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
        @param dst_q A queue that should be used to forward all snapshot
            data to
        @param snapshot_id The UUID of the requested snapshot
        @param time_delta A timedelta object to mark the snapshot size
        """
        # Threat Bus follows a hierarchical pub-sub structure. Subscriptions
        # to 'threatbus' must hence result in snapshots for both, intel
        # and sightings
        message_types = []
        prefix = "threatbus"
        if topic == prefix:
            message_types = [MessageType.INTEL, MessageType.SIGHTING]
        elif topic.endswith("sighting"):
            message_types.append(MessageType.SIGHTING)
        elif topic.endswith("intel"):
            message_types.append(MessageType.INTEL)
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
        logging = self.config["logging"]
        self.backbones.run(
            config=self.config["plugins"]["backbones"], logging=logging, inq=self.inq
        )
        self.subscribe("threatbus/snapshotrequest", self.snapshot_q)
        self.subscribe("threatbus/snapshotenvelope", self.snapshot_q)
        self.apps.run(
            config=self.config["plugins"]["apps"],
            logging=logging,
            inq=self.inq,
            subscribe_callback=self.subscribe,
            unsubscribe_callback=self.unsubscribe,
        )
        self.handle_snapshots()


def validate_config(config: confuse.Subview):
    if config["logging"]["console"].get(bool):
        config["logging"]["console_verbosity"].get(str)
    if config["logging"]["file"].get(bool):
        config["logging"]["file_verbosity"].get(str)
        config["logging"]["filename"].get(str)


def start(config: confuse.Subview):
    try:
        validate_config(config)
    except Exception as e:
        raise ValueError("Invalid config: {}".format(str(e)))

    backbones = pluggy.PluginManager("threatbus.backbone")
    backbones.add_hookspecs(backbonespecs)
    backbones.load_setuptools_entrypoints("threatbus.backbone")

    apps = pluggy.PluginManager("threatbus.app")
    apps.add_hookspecs(appspecs)
    apps.load_setuptools_entrypoints("threatbus.app")

    tb_logger = logger.setup(config["logging"], "threatbus")
    configured_apps = set(config["plugins"]["apps"].keys())
    installed_apps = set(dict(apps.list_name_plugin()).keys())
    for unwanted_app in installed_apps - configured_apps:
        tb_logger.info(f"Disabling installed, but unconfigured app '{unwanted_app}'")
        apps.unregister(name=unwanted_app)
    configured_backbones = set(config["plugins"]["backbones"].keys())
    installed_backbones = set(dict(backbones.list_name_plugin()).keys())
    for unwanted_backbones in installed_backbones - configured_backbones:
        tb_logger.info(
            f"Disabling installed, but unconfigured backbones '{unwanted_backbones}'"
        )
        backbones.unregister(name=unwanted_backbones)

    bus_thread = ThreatBus(backbones.hook, apps.hook, tb_logger, config)
    signal.signal(signal.SIGINT, bus_thread.stop_signal)
    bus_thread.start()
    return bus_thread


def main():
    config = confuse.Configuration("threatbus")
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="path to a configuration file")
    args = parser.parse_args()
    config.set_args(args)
    if args.config:
        config.set_file(args.config)
    start(config)


if __name__ == "__main__":
    main()
