class ZeekConfig:
    """Helper to instruct Zeek objects under test with a configuration"""

    def __init__(self, host, port, topic):
        self.host = host
        self.port = port
        self.topic = topic


class VastConfig:
    """Helper to instruct VAST objects under test with a configuration"""

    def __init__(self, executable, time_window, max_results):
        self.executable = executable
        self.time_window = time_window
        self.max_results = max_results


class MispRestConfig:
    def __init__(self, api_key, url, ssl):
        self.api_key = api_key
        self.url = url
        self.ssl = ssl


class MispZmqConfig:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class MispKafkaConfig:
    def __init__(self, attribute_topic):
        # TODO: generate this.
        self.attribute_topic = attribute_topic


class MispSnapshotConfig:
    def __init__(self, raw, search):
        # TODO: generate this.
        self.raw = raw
        self.search = search


class MispConfig:
    """Helper to instruct MISP objects under test with a configuration"""

    def __init__(
        self,
        rest_config: MispRestConfig,
        zmq_config: MispZmqConfig,
        kafka_config: MispKafkaConfig,
        snapshot_config: MispSnapshotConfig,
    ):
        self.rest = rest_config
        self.zmq = zmq_config
        self.kafka = kafka_config
        self.snapshot = snapshot_config
