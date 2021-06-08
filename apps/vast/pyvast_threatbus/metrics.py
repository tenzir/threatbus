from datetime import datetime
from threading import Lock
from sys import maxsize as max_integer


class Metric:
    """
    A simple, thread-safe metric class with a name and a creation date. Can be
    resetted to initial values by calling reset().
    """

    def __init__(self, name: str):
        self.name = name
        self.ts = datetime.now()
        self.is_set = False  # indicator if the metric was touched
        self._lock = Lock()

    def reset(self):
        """
        Reset all values of the metric
        """
        self.ts = datetime.now()
        with self._lock:
            self.is_set = False


class Summary(Metric):
    """
    A simple numeric summary metric
    """

    def __init__(self, name: str):
        super(Summary, self).__init__(name)
        self._count = 0  # invocation count
        self._sum = 0  # sum of all values
        self.min = max_integer  # minimum reported value
        self.max = 0  # maximum reported value
        self.avg = 0  # average of all reported values

    def observe(self, value: int):
        """
        Store an observation to be part of this summary
        """
        with self._lock:
            self.is_set = True
            self._count += 1
            self._sum += value
            self.min = min(self.min, value)
            self.max = max(self.max, value)
            if self._count > 0:
                self.avg = self._sum / self._count

    def reset(self):
        super(Summary, self).reset()
        with self._lock:
            self._count = 0
            self._sum = 0
            self.min = max_integer
            self.max = 0
            self.avg = 0


class Gauge(Metric):
    """
    A simple numeric gauge that can go up and down
    """

    def __init__(self, name: str):
        super(Gauge, self).__init__(name)
        self.value = 0

    def inc(self):
        """
        Increase the gauge value
        """
        with self._lock:
            self.is_set = True
            self.value += 1

    def dec(self):
        """
        Decrease the gauge value
        """
        with self._lock:
            self.is_set = True
            self.value -= 1

    def reset(self):
        super(Gauge, self).reset()
        with self._lock:
            self.value = 0


class InfiniteGauge(Gauge):
    """
    A simple numeric gauge that can go up and down. This gauge can never be
    resetted by a function call. Instead, it resets automatically when it's
    value reaches the initial value of `0`.
    """

    def __init__(self, name: str):
        super(InfiniteGauge, self).__init__(name)
        self.value = 0
        self.initial_value = 0

    def __reset(self):
        super(InfiniteGauge, self).reset()

    def reset(self):
        pass

    def inc(self):
        """
        Increase the gauge value. Automatically resets it in case the value
        equals 0 after this operation.
        """
        super(InfiniteGauge, self).inc()
        if self.value == self.initial_value:
            self.__reset()

    def dec(self):
        """
        Decrease the gauge value. Automatically resets it in case the value
        equlas 0 after this operation.
        """
        super(InfiniteGauge, self).dec()
        if self.value == self.initial_value:
            self.__reset()
