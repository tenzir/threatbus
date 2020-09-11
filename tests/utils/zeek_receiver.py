#!/usr/bin/python

import broker
from datetime import timedelta
import select


def receive(items, topic="threatbus/intel", td=timedelta(days=0)):
    ep = broker.Endpoint()
    ep.peer("127.0.0.1", 47761)
    subscribe_event = broker.zeek.Event("Tenzir::subscribe", topic, td)
    ep.publish("threatbus/manage", subscribe_event)
    manage = ep.make_subscriber("threatbus/manage")
    fd_sets = select.select([manage.fd()], [], [])
    if not fd_sets[0]:
        print("Peering with remote machine failed.")
        return
    _, data = manage.get()
    topic = broker.zeek.Event(data).args()[0]
    subscriber = ep.make_subscriber(topic)

    for _ in range(items):
        fd_sets = select.select([subscriber.fd()], [], [])
        if not fd_sets[0]:
            print("Receiving data from Threat Bus failed.")
            return
        _, data = subscriber.get()
        yield broker.zeek.Event(data)
    unsubscribe_event = broker.zeek.Event("Tenzir::unsubscribe", topic)
    ep.publish("threatbus/manage", unsubscribe_event)


def forward(items, q, topic="threatbus/intel"):
    """
    Receives the requested amount of items and forwards them to a queue.Queue
    """
    for item in receive(items, topic):
        q.put(item)


if __name__ == "__main__":
    for received_event in receive(200):
        print(
            "received event   name: {}    content: {}".format(
                received_event.name(), received_event.args()
            )
        )
