#!/usr/bin/python

import broker
import select

ep = broker.Endpoint()
subscriber = ep.make_subscriber("tenzir/threatbus")
ep.peer("127.0.0.1", 47761)

while True:

    fd_sets = select.select([subscriber.fd()], [], [])
    if not fd_sets[0]:
        print("boom. this is the end.")

    (topic, data) = subscriber.get()
    received_event = broker.zeek.Event(data)

    print(
        "received on topic: {}    event name: {}    content: {}".format(
            topic, received_event.name(), received_event.args()
        )
    )
