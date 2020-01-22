from confluent_kafka import Producer
import time

bootstrap_servers = "PLAINTEXT://172.17.0.1:9092"
topic = "misp_attribute"
producer = Producer({"bootstrap.servers": bootstrap_servers})
producer.produce(topic, b"my_value", b"my_key")

# wait before exiting, else the event does not get sent properly
time.sleep(1)
