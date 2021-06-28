from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
from multiprocessing import JoinableQueue
import pluggy
from typing import Callable, List
from threatbus.data import SnapshotRequest

hookspec = pluggy.HookspecMarker("threatbus.app")


@hookspec
def run(
    config: DynaBox,
    logging: DynaBox,
    inq: JoinableQueue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    """
    Runs / starts a plugin spec with a configuration object
    @param config A configuration object for the app
    @param logging A configuration object for the logger
    @param inq A queue in which this plugin puts incoming messages
    @param subscribe_callback A callback to use by a plugin to notify about
        new subscriptions
    @param unsubscribe_callback A callback to use by a plugin to notify
        about subscription revocations
    """


@hookspec
def stop():
    """Stops all Threads that the plugin has started."""


@hookspec
def snapshot(snapshot_request: SnapshotRequest, result_q: JoinableQueue):
    """
    Perform a snapshot, based on the given `snapshot_request`. Snapshots are
    collected up to the requested earliest date. Results of the type
    threatbus.data.SnapshotEnvelope are put to the result_q.
    @param snapshot_request @see threatbus.data.SnapshotRequest
    @param result_q Snapshot results are forwarded to this queue
    """


@hookspec
def config_validators() -> List[Validator]:
    """
    Returns a list of dynaconf.Validators so the main Threat Bus runtime can
    validate the user-specified configuration.
    """
