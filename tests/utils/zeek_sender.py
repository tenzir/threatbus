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

        event = broker.zeek.Event("sighting", datetime.timestamp(datetime.now()), i, {})
        ep.publish("foo", event)

    ## apparently the receiver will not receive everything, if the sending process exits too early. Thus we wait here (just for the demo sake)
    time.sleep(1)


if __name__ == "__main__":
    send(10)
