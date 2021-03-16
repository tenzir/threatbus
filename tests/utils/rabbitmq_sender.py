import pika
from stix2 import Indicator

## Dummy intel data
pattern = "[ipv4-addr:value = '6.6.6.6']"
pattern_type = "stix2"
indicator = Indicator(pattern=pattern, pattern_type=pattern_type)
indicator_json = indicator.serialize()
## rabbitmq
host = "localhost"
port = "5672"
vhost = "/"
credentials = pika.PlainCredentials("guest", "guest")
conn_params = pika.ConnectionParameters(host, port, vhost, credentials)

connection = pika.BlockingConnection(conn_params)
channel = connection.channel()

for i in range(100):
    channel.basic_publish(exchange="threatbus", routing_key="", body=indicator_json)
