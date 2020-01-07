#!/usr/bin/python

import broker
import select
import sys


def receive(items):
    ep = broker.Endpoint()
    subscriber = ep.make_subscriber("tenzir/threatbus")
    ep.peer("127.0.0.1", 47761)

    for _ in range(items):
        fd_sets = select.select([subscriber.fd()], [], [])
        if not fd_sets[0]:
            print("boom. this is the end.")
            sys.exit(1)
        (topic, data) = subscriber.get()
        yield topic, broker.zeek.Event(data)


def forward(items, q):
    """Receives the requested amount of items and forwards them to a queue.Queue"""
    for item in receive(items):
        q.put(item)


if __name__ == "__main__":
    for (topic, received_event) in receive(10):
        print(
            "received on topic: {}    event name: {}    content: {}".format(
                topic, received_event.name(), received_event.args()
            )
        )
