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
