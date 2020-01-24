import pluggy

hookspec = pluggy.HookspecMarker("threatbus.app")


@hookspec
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
    """Runs / starts a plugin spec with a configuration object
        @param config A configuration object for the app
        @param logging A configuration object for the logger
        @param inq A queue in which this plugin puts incoming messages
        @param subscribe_callback A callback to use by a plugin to notify about
            new subscriptions
        @param unsubscribe_callback A callback to use by a plugin to notify
            about subscription revocations
    """


@hookspec
def snapshot(snapshot_type, result_q, time_delta):
    """Requests a snapshot from the implementing plugin. Snapshot are returned
        up to the requested earliest date. Results are put to the result_q.
        @param snapshot_type @see threatbus.data.MessageType
        @param result_q Snapshot results are forwarded to this queue
        @param time_delta A datetime.timedelta object to mark the snapshot size
    """
