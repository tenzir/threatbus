#!/usr/bin/python
from datetime import datetime
import broker
import sys
import time


def send(items):
    ep = broker.Endpoint()
    status_subscriber = ep.make_status_subscriber(True)
    ep.peer("127.0.0.1", 47761)

    # blocking operation. wait until you get a status.
    status = status_subscriber.get()

    if type(status) != broker.Status or status.code() != broker.SC.PeerAdded:
        print("peering with remote machine failed")
        sys.exit(1)

    for i in range(items):
        data = {
            "indicator": "example.com",
            "intel_type": "DOMAIN",
        }
        event = broker.zeek.Event("intel", datetime.now(), i, data, "ADD")

        # threat-bus will pickup the event type "sighting" and hence forward on
        # a different topic.
        ep.publish("tenzir/some-zeek-topic", event)

    ## apparently the receiver will not receive everything, if the sending process exits too early. Thus we wait here (just for the demo sake)
    time.sleep(1)


if __name__ == "__main__":
    send(1)
