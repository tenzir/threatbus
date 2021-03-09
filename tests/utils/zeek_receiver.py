#!/usr/bin/python

import broker
from datetime import timedelta
import select


def subscribe(ep, topic, time_delta=timedelta(days=0)):
    """
    Subscribes via the Zeek plugin's management endpoint to a Broker topic.
    @return a tuple of a (Broker.Subscriber, p2p_topic).
    """

    subscribe_event = broker.zeek.Event("Tenzir::subscribe", topic, time_delta)
    ep.publish("threatbus/manage", subscribe_event)
    manage = ep.make_subscriber("threatbus/manage")
    fd_sets = select.select([manage.fd()], [], [])
    if not fd_sets[0]:
        print("Peering with remote machine failed.")
        return
    _, data = manage.get()
    p2p_topic = broker.zeek.Event(data).args()[0]
    return p2p_topic


def unsubscribe(ep, topic):
    """
    Unsubscribes via the Zeek plugin's management endpoint from a Broker topic.
    """
    unsubscribe_event = broker.zeek.Event("Tenzir::unsubscribe", topic)
    ep.publish("threatbus/manage", unsubscribe_event)


def receive(items, topic="stix2/indicator", time_delta=timedelta(days=0)):
    host, port = "127.0.0.1", 47761
    ep = broker.Endpoint()
    ep.peer(host, port)
    p2p_topic = subscribe(ep, topic, time_delta)
    subscriber = ep.make_subscriber(p2p_topic)
    for _ in range(items):
        fd_sets = select.select([subscriber.fd()], [], [])
        if not fd_sets[0]:
            print("Receiving data from Threat Bus failed.")
            return
        _, data = subscriber.get()
        yield broker.zeek.Event(data)
    unsubscribe(ep, p2p_topic)


def forward(items, q, topic="stix2/indicator"):
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
