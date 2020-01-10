#!/usr/bin/python

import broker
import select
import sys


def receive(items, topic="tenzir/threatbus/intel"):
    ep = broker.Endpoint()
    subscriber = ep.make_subscriber(topic)
    ep.peer("127.0.0.1", 47761)

    for _ in range(items):
        fd_sets = select.select([subscriber.fd()], [], [])
        if not fd_sets[0]:
            print("boom. this is the end.")
            sys.exit(1)
        _, data = subscriber.get()
        yield broker.zeek.Event(data)


def forward(items, q, topic="tenzir/threatbus/intel"):
    """Receives the requested amount of items and forwards them to a queue.Queue"""
    for item in receive(items, topic):
        q.put(item)


if __name__ == "__main__":
    for received_event in receive(200):
        print(
            "received event   name: {}    content: {}".format(
                received_event.name(), received_event.args()
            )
        )
