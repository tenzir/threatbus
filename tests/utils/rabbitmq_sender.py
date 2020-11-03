from datetime import datetime
import json
import pika
from threatbus.data import Intel, IntelData, IntelType, Operation, IntelEncoder

## Dummy intel data
intel_id = "intel-42"
indicator = "6.6.6.6"
intel_type = IntelType.IPSRC
operation = Operation.ADD
intel_data = IntelData(indicator, intel_type, foo=23, more_args="MORE ARGS")
intel = Intel(
    datetime.strptime("2020-11-02 17:00:00", "%Y-%m-%d %H:%M:%S"),
    intel_id,
    intel_data,
    operation,
)

intel_json = json.dumps(intel, cls=IntelEncoder)

## rabbitmq
host = "localhost"
port = "5672"
vhost = "/"
credentials = pika.PlainCredentials("guest", "guest")
conn_params = pika.ConnectionParameters(host, port, vhost, credentials)

connection = pika.BlockingConnection(conn_params)
channel = connection.channel()

for i in range(100):
    channel.basic_publish(exchange="threatbus.intel", routing_key="", body=intel_json)
