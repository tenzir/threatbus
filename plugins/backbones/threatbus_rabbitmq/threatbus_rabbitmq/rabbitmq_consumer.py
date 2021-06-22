from dynaconf.utils.boxing import DynaBox
import json
import pika
from logging import Logger
from stix2 import Indicator, Sighting, parse
import threatbus
from threatbus.data import (
    SnapshotRequest,
    SnapshotEnvelope,
    SnapshotRequestDecoder,
    SnapshotEnvelopeDecoder,
)
import time
from typing import Callable, List, Union


class RabbitMQConsumer(threatbus.StoppableWorker):
    """
    Connects to RabbitMQ on the given host/port endpoint. Registers callbacks to
    consumes all messages and initiates further provisioning.
    """

    def __init__(
        self,
        conn_params: pika.ConnectionParameters,
        exchange_name: str,
        queue_params: DynaBox,
        provision_callback: Callable[
            [str, Union[Indicator, Sighting, SnapshotEnvelope, SnapshotRequest]], None
        ],
        logger: Logger,
    ):
        """
        @param conn_params Pika.ConnectionParameters to connect to RabbitMQ
        @param exchange_name The name of the RabbitMQ Threat Bus exchange
        @param queue_params DynaBox config parameters to use for declaring queues
        @param provision_callback A callback to invoke after messages are retrieved and parsed successfully
        @param logger A pre-configured Logger instance
        """
        super(RabbitMQConsumer, self).__init__()
        self.conn_params: pika.ConnectionParameters = conn_params
        self.__provision_callback: Callable[
            [str, Union[Indicator, Sighting, SnapshotEnvelope, SnapshotRequest]], None
        ] = provision_callback
        self.logger: Logger = logger
        self.consumers: List[str] = list()  # RabbitMQ consumer tags
        self.exchange_name = exchange_name
        self._reconnect_delay: int = 5
        self._connection: Union[pika.SelectConnection, None] = None
        self._channel: Union[pika.channel.Channel, None] = None

        # Create names and parameters for exchanges and queues
        join_symbol = queue_params.name_join_symbol
        queue_name_suffix = queue_params.name_suffix
        self.queue_name = f"threatbus{join_symbol}{queue_name_suffix}"

        queue_mode = "default" if not queue_params.lazy else "lazy"
        self.queue_kwargs = {
            "durable": queue_params.durable,
            "exclusive": queue_params.exclusive,
            "auto_delete": queue_params.auto_delete,
            "arguments": {"x-queue-mode": queue_mode},
        }
        if queue_params.max_items:
            self.queue_kwargs["arguments"]["x-max-length"] = queue_params.max_items

    def __provision(self, _channel, method_frame, _header_frame, msg):
        """
        Callback to be invoked by the Pika library whenever a new message `msg` has
        been received from RabbitMQ on the intel queue.
        @param channel: pika.Channel The channel that was received on
        @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
        @param properties: pika.spec.BasicProperties Pika properties
        @param msg: bytes The received message
        """
        msg_type = None
        try:
            dct = json.loads(msg)
            msg_type = dct.get("type", None)
        except Exception as e:
            self.logger.error(f"RabbitMQ consumer: error reading message {msg}: {e}")

        try:
            if msg_type == "indicator" or msg_type == "sighting":
                self.__provision_callback(
                    f"stix2/{msg_type}", parse(msg, allow_custom=True)
                )
            elif msg_type == "snapshotrequest":
                self.__provision_callback(
                    f"threatbus/{msg_type}", json.loads(msg, cls=SnapshotRequestDecoder)
                )
            elif msg_type == "snapshotenvelope":
                self.__provision_callback(
                    f"threatbus/{msg_type}",
                    json.loads(msg, cls=SnapshotEnvelopeDecoder),
                )
            else:
                self.logger.error(
                    f"RabbitMQ consumer: received message with unknown or missing 'type' field {msg}"
                )
        except Exception as e:
            self.logger.error(f"RabbitMQ consumer: error decoding message {msg}: {e}")

        self._channel.basic_ack(delivery_tag=method_frame.delivery_tag)

    def __shutdown(self):
        """
        Cancels the consumers and stops the RabbitMQ connection
        """
        self._connection.ioloop.stop()

    def join(self, *args, **kwargs):
        """
        Stops the RabbitMQ connection, disables automatic reconnection, and
        forwards the join() call to the super class, i.e., the stop event will
        be set, such that the semi-infinite run() method can exit.
        """
        self._reconnect_delay = 0
        self.__shutdown()
        super(RabbitMQConsumer, self).join(*args, **kwargs)

    def on_connection_open(self, _connection: pika.connection.Connection):
        """
        Invoked as callback when opening a new pika.SelectConnecion.
        Issues opening of a channel.
        @param _connection The opened connection
        """
        self._connection.channel(on_open_callback=self.on_channel_open)

    def on_connection_open_error(
        self, _connection: pika.connection.Connection, err: Exception
    ):
        """
        Invoked as callback when opening a new pika.SelectConnecion.
        Issues opening of a channel.
        @param _connection The opened connection
        """
        self.logger.error(f"RabbitMQ consumer: connection failed to open {err}")
        self.__shutdown()  # will restart automatically

    def on_connection_closed(
        self, _connection: pika.connection.Connection, reason: Exception
    ):
        """
        Invoked when the connection to RabbitMQ is closed unexpectedly. Tries to
        reconnect.
        @param connection The closed connection
        @param reason Exception representing reason for loss of connection
        """
        self.logger.warning(
            f"RabbitMQ consumer: connection closed unexpectedly. Reason: {reason}"
        )
        self.__shutdown()  # will restart automatically

    def on_channel_open(self, channel):
        """
        Invoked as callback from connection.channel. See self.on_connecion_open
        @param channel The successfully opened channel
        """
        self._channel = channel
        self._channel.add_on_close_callback(self.on_channel_closed)

        self._channel.exchange_declare(
            exchange=self.exchange_name,
            exchange_type="fanout",
            callback=self.on_exchange_declare_ok,
        )

    def on_channel_closed(self, channel: pika.channel.Channel, reason: Exception):
        """
        Invoked when RabbitMQ closes the channel unexpectedly.
        Channels are usually closed if you attempt to do something that
        violates the protocol, such as re-declare an exchange or queue with
        different parameters. In this case, we'll close the connection
        to shutdown the object.
        @param channel The closed channel
        @param reason The Exception the channel was closed
        """
        self.logger.warning(f"RabbitMQ consumer: channel closed unexpectedly: {reason}")
        self.__shutdown()  # will restart automatically

    def on_exchange_declare_ok(self, _frame):
        """
        Invoked as callback from exchange_declare. See self.on_channel_open.
        Issues declaration of the queues.
        @param _frame Unused pika response
        """
        queue_kwargs = self.queue_kwargs.copy()
        queue_kwargs["callback"] = self.on_queue_declare_ok
        self._channel.queue_declare(queue=self.queue_name, **queue_kwargs)

    def on_queue_declare_ok(self, _frame):
        """
        Binds the freshly declared queue to the exchange.
        @param _frame Unused pika response
        """
        self._channel.queue_bind(
            exchange=self.exchange_name,
            queue=self.queue_name,
            callback=self.on_queue_bind_ok,
        )

    def on_queue_bind_ok(self, _frame):
        """
        Inspects the given userdata (exchange_name, queue_name) and binds the queue to the exchange.
        @param _frame Unused pika response
        @param userdata The name of the bound queue queue_name
        """
        self.consumer = self._channel.basic_consume(self.queue_name, self.__provision)

    def run(self):
        """
        Starts a RabbitMQ connection in a semi-infinite loop that reconnects
        automatically on failure.
        """
        while self._running():
            self.logger.debug("RabbitMQ consumer: connecting...")
            self._connection = pika.SelectConnection(
                parameters=self.conn_params,
                on_open_callback=self.on_connection_open,
                on_open_error_callback=self.on_connection_open_error,
                on_close_callback=self.on_connection_closed,
            )
            self._connection.ioloop.start()

            time.sleep(self._reconnect_delay)
