from threading import Event, Thread


class StoppableWorker(Thread):
    """
    A threading.Thread with a dedicated method, called _running(), for checking
    if the thread should continue running. Invoking it's join() method changes
    the return value of _running(). Use this method as exit condition to model
    semi-infinite loops.
    """

    def __init__(self):
        super(StoppableWorker, self).__init__()
        self._stop_event = Event()

    def __stop(self):
        self._stop_event.set()

    def _running(self):
        return not self._stop_event.is_set()

    def join(self, *args, **kwargs):
        self.__stop()
        super(StoppableWorker, self).join(*args, **kwargs)
