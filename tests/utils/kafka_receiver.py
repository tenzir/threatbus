from confluent_kafka import Consumer, KafkaException
import json

# See https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
bootstrap_servers = "localhost:9092"
group_id = "threatbus"
topics = ["misp_attribute", "intel"]


def receive(count):
    conf = {
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "auto.offset.reset": "earliest",
    }
    consumer = Consumer(conf)
    consumer.subscribe(topics)
    try:
        for _ in range(count):
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            yield (msg)
    except KeyboardInterrupt:
        pass

    finally:
        consumer.close()


if __name__ == "__main__":
    for msg in receive(1000):
        if msg.error():
            print(f"error: {KafkaException(msg.error())}")
        else:
            print(f"topic: {msg.topic()}, key: {msg.key()}, message: {msg.value()}")
