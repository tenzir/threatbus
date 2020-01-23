#!/usr/bin/python

import broker
from datetime import timedelta
import select
import sys


def receive(items, topic="threatbus/intel"):
    ep = broker.Endpoint()
    ep.peer("127.0.0.1", 47761)
    td = timedelta(days=0)
    subscribe_event = broker.zeek.Event("Tenzir::subscribe", topic, td)
    ep.publish("threatbus/manage", subscribe_event)
    manage = ep.make_subscriber("threatbus/manage")
    _, data = manage.get()
    topic = broker.zeek.Event(data).args()[0]
    subscriber = ep.make_subscriber(topic)

    for _ in range(items):
        fd_sets = select.select([subscriber.fd()], [], [])
        if not fd_sets[0]:
            print("boom. this is the end.")
            sys.exit(1)
        _, data = subscriber.get()
        yield broker.zeek.Event(data)


def forward(items, q, topic="threatbus/intel"):
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
