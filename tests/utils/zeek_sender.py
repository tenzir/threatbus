#!/usr/bin/python
import broker
from datetime import datetime
import select
from stix2 import Sighting
import time


def send(topic, broker_event):
    """Sends a single, user specified broker event"""
    ep = broker.Endpoint()
    status_subscriber = ep.make_status_subscriber(True)
    ep.peer("127.0.0.1", 47761)

    fd_sets = select.select([status_subscriber.fd()], [], [])
    if not fd_sets[0]:
        print("Peering with remote machine failed")
        return
    status = status_subscriber.get()
    if type(status) != broker.Status or status.code() != broker.SC.PeerAdded:
        print("Threat Bus subscription failed")
        return

    ep.publish(topic, broker_event)
    time.sleep(0.1)


def send_generic(topic, items):
    ep = broker.Endpoint()
    status_subscriber = ep.make_status_subscriber(True)
    ep.peer("127.0.0.1", 47761)

    fd_sets = select.select([status_subscriber.fd()], [], [])
    if not fd_sets[0]:
        print("Peering with remote machine failed")
        return
    status = status_subscriber.get()
    if type(status) != broker.Status or status.code() != broker.SC.PeerAdded:
        print("Threat Bus subscription failed")
        return

    for _ in range(items):
        event = broker.zeek.Event(
            "sighting",
            datetime.now(),
            "indicator--cdd5791f-916e-4f62-8090-1a006005af76",
            {},
        )

        # Threat Bus will pickup the event type and hence forward on a different
        # topic.
        ep.publish(topic, event)

    # apparently the receiver will not receive everything, if the sending process exits too early.
    time.sleep(1)


if __name__ == "__main__":
    send_generic("stix2/sighting", 1)
