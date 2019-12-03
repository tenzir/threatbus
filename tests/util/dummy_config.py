class DummyConfig:
    """Helper to instruct objects under test with a configuration"""

    def __init__(self, host, port, topic):
        self.host = host
        self.port = port
        self.topic = topic
