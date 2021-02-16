import json
import pika
from logging import Logger
from multiprocessing import JoinableQueue
from queue import Empty
from retry import retry
from stix2 import Indicator, Sighting
import threatbus
from threatbus.data import (
    SnapshotRequest,
    SnapshotEnvelope,
    SnapshotRequestEncoder,
    SnapshotEnvelopeEncoder,
)
from typing import Union


class RabbitMQPublisher(threatbus.StoppableWorker):
    """
    Connects to RabbitMQ on the given host/port endpoint. Forwards all messages
    from the `inq`, based on their type, to the appropriate RabbitMQ exchange.
    """

    def __init__(
        self,
        conn_params: pika.ConnectionParameters,
        exchange_name: str,
        inq: JoinableQueue,
        logger: Logger,
    ):
        """
        @param conn_params Pika.ConnectionParameters to connect to RabbitMQ
        @param exchange_name The name of the RabbitMQ Threat Bus exchange
        @param join_symbol The symbol to use when determining queue and exchange names
        @param inq A queue object to read messages from and publish them to RabbitMQ
        @param logger A pre-configured Logger instance
        """
        super(RabbitMQPublisher, self).__init__()
        self.conn_params = conn_params
        self.exchange_name = exchange_name
        self.inq: JoinableQueue = inq
        self.logger: Logger = logger
        self.should_connect: bool = True
        self._reconnect_delay: int = 5
        self._connection: Union[pika.BlockingConnection, None] = None
        self._channel: Union[pika.channel.Channel, None] = None

    def join(self, *args, **kwargs):
        """
        Stops the RabbitMQ connection, disables automatic reconnection, and
        forwards the join() call to the super class, i.e., the stop event will
        be set, such that the semi-infinite run() method can exit.
        """
        self.should_connect = False
        if self._channel:
            self._channel.close()
        if self._connection:
            self._connection.close()
        super(RabbitMQPublisher, self).join(*args, **kwargs)

    @retry(delay=5)
    def __connect(self):
        if not self.should_connect:
            return
        try:
            self.logger.debug("RabbitMQ publisher: connecting...")
            self.connection = pika.BlockingConnection(self.conn_params)
        except KeyboardInterrupt:
            return
        except Exception as e:
            self.logger.error("RabbitMQ publisher: connection failed to open.")
            raise Exception("Connection failed") from e
        self.channel = self.connection.channel()
        self.channel.exchange_declare(
            exchange=self.exchange_name, exchange_type="fanout"
        )

    def run(self):
        self.__connect()
        while self._running():
            try:
                msg = self.inq.get(block=True, timeout=1)
            except Empty:
                continue
            encoded_msg = None
            try:
                if type(msg) == Indicator or type(msg) == Sighting:
                    encoded_msg = msg.serialize()
                elif type(msg) == SnapshotRequest:
                    encoded_msg = json.dumps(msg, cls=SnapshotRequestEncoder)
                elif type(msg) == SnapshotEnvelope:
                    encoded_msg = json.dumps(msg, cls=SnapshotEnvelopeEncoder)
                else:
                    self.logger.warn(
                        f"RabbitMQ publisher: discarding message with unknown type: {msg}"
                    )
                    self.inq.task_done()
                    continue
            except Exception as e:
                self.logger.warn(
                    f"RabbitMQ publisher: discarding unparsable message {msg}: {e}"
                )
                self.inq.task_done()
                continue
            try:
                self.channel.basic_publish(
                    exchange=self.exchange_name, routing_key="", body=encoded_msg
                )
                self.inq.task_done()
                self.logger.debug(
                    f"RabbitMQ publisher: forwarded message to RabbitMQ: {msg}"
                )
            except Exception as e:
                self.logger.error(f"RabbitMQ publisher: failed to publish: {e}")
                if msg:
                    self.inq.put(msg)
                    self.inq.task_done()
                    self.logger.error(
                        f"RabbitMQ publisher: pushing back message {msg}: {e}"
                    )
                self.__connect()
