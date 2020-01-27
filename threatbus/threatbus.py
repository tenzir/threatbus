import argparse
import confuse
import pluggy
from queue import Queue
import time
from threatbus import appspecs, backbonespecs, logger
from threatbus.data import MessageType


class ThreatBus:
    def __init__(self, backbones, apps, config):
        self.backbones, self.apps = backbones, apps
        self.config = config
        self.logger = logger.setup(config["logging"], "threatbus")
        self.inq = Queue()

    def request_snapshot(self, topic, dst_q, time_delta):
        """Request a snapshot from all registered apps for a given topic.
            @param topic The topic for which the snapshot is requested
            @param dst_q A queue that should be used to forward all snapshot
                data to
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
        snapshot_q = Queue()  # fan-in queue for this particular snapshot
        for mt in message_types:
            self.logger.info(
                f"Requesting snapshot from all plugins for message type {mt.name} and time delta {time_delta}"
            )
            self.apps.snapshot(
                snapshot_type=mt, result_q=snapshot_q, time_delta=time_delta
            )
        if message_types:
            self.backbones.provision_p2p(src_q=snapshot_q, dst_q=dst_q)

    def subscribe(self, topic, q, time_delta=None):
        """Accepts a new subscription for a given topic and queue pointer.
            Forwards that subscription to all managed backbones.
            @param topic Subscribe to this topic
            @param q A queue object to forward all messages for the given topics
            @param time_delta A timedelta object to mark the snapshot size
        """
        assert isinstance(topic, str), "topic must be string"
        self.backbones.subscribe(topic=topic, q=q)
        if time_delta:
            self.request_snapshot(topic, q, time_delta)

    def unsubscribe(self, topic, q):
        """Removes subscription for a given topic and queue pointer from all managed backbones."""
        assert isinstance(topic, str), "topic must be string"
        self.backbones.unsubscribe(topic=topic, q=q)

    def run(self):
        self.logger.info("Starting plugins...")
        logging = self.config["logging"]
        self.apps.run(
            config=self.config["plugins"]["apps"],
            logging=logging,
            inq=self.inq,
            subscribe_callback=self.subscribe,
            unsubscribe_callback=self.unsubscribe,
        )
        self.backbones.run(
            config=self.config["plugins"]["backbones"], logging=logging, inq=self.inq
        )
        while True:
            time.sleep(1)


def validate_config(config):
    config["logging"]["console"].get(bool)
    config["logging"]["file"].get(bool)
    config["logging"]["console_verbosity"].get(str)
    config["logging"]["file_verbosity"].get(str)
    config["logging"]["filename"].get(str)


def main():
    backbones = pluggy.PluginManager("threatbus.backbone")
    backbones.add_hookspecs(backbonespecs)
    backbones.load_setuptools_entrypoints("threatbus.backbone")

    apps = pluggy.PluginManager("threatbus.app")
    apps.add_hookspecs(appspecs)
    apps.load_setuptools_entrypoints("threatbus.app")

    config = confuse.Configuration("threatbus")
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="path to a configuration file")
    args = parser.parse_args()
    config.set_args(args)
    if args.config:
        config.set_file(args.config)

    try:
        validate_config(config)
    except Exception as e:
        raise ValueError("Invalid config: {}".format(str(e)))
    bus = ThreatBus(backbones.hook, apps.hook, config)
    bus.run()


if __name__ == "__main__":
    main()
