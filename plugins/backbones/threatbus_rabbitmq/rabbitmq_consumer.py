from confuse import Subview
from functools import partial
import json
import pika
from logging import Logger
from threatbus_rabbitmq import get_exchange_name, get_queue_name
from socket import gethostname
import threatbus
from threatbus.data import (
    Intel,
    Sighting,
    SnapshotRequest,
    SnapshotEnvelope,
    IntelDecoder,
    SightingDecoder,
    SnapshotRequestDecoder,
    SnapshotEnvelopeDecoder,
)
import time
from typing import Callable, List, Tuple, Union


class RabbitMQConsumer(threatbus.StoppableWorker):
    """
    Connects to RabbitMQ on the given host/port endpoint. Registers callbacks to
    consumes all messages and initiates further provisioning.
    """

    def __init__(
        self,
        conn_params: pika.ConnectionParameters,
        join_symbol: str,
        queue_params: Subview,
        provision_callback: Callable[
            [str, Union[Intel, Sighting, SnapshotEnvelope, SnapshotRequest]], None
        ],
        logger: Logger,
    ):
        """
        @param conn_params Pika.ConnectionParameters to connect to RabbitMQ
        @param join_symbol The symbol to use when determining queue and exchange names
        @param queue_params Confuse view of parameters to use for declaring queues
        @param provision_callback A callback to invoke after messages are retrieved and parsed successfully
        @param logger A pre-configured Logger instance
        """
        super(RabbitMQConsumer, self).__init__()
        self.conn_params: pika.ConnectionParameters = conn_params
        self.__provision: Callable[
            [str, Union[Intel, Sighting, SnapshotEnvelope, SnapshotRequest]], None
        ] = provision_callback
        self.logger: Logger = logger
        self.consumers: List[str] = list()  # RabbitMQ consumer tags
        self._reconnect_delay: int = 5
        self._connection: Union[pika.SelectConnection, None] = None
        self._channel: Union[pika.channel.Channel, None] = None

        # Create names and parameters for exchanges and queues
        self.intel_exchange = get_exchange_name(join_symbol, "intel")
        self.sighting_exchange = get_exchange_name(join_symbol, "sighting")
        self.snapshot_request_exchange = get_exchange_name(
            join_symbol, "snapshotrequest"
        )
        self.snapshot_envelope_exchange = get_exchange_name(
            join_symbol, "snapshotenvelope"
        )
        queue_name_suffix = queue_params["name_suffix"].get()
        queue_name_suffix = queue_name_suffix if queue_name_suffix else gethostname()
        self.intel_queue = get_queue_name(join_symbol, "intel", queue_name_suffix)
        self.sighting_queue = get_queue_name(join_symbol, "sighting", queue_name_suffix)
        self.snapshot_request_queue = get_queue_name(
            join_symbol, "snapshotrequest", queue_name_suffix
        )
        self.snapshot_envelope_queue = get_queue_name(
            join_symbol, "snapshotenvelope", queue_name_suffix
        )
        queue_mode = "default" if not queue_params["lazy"].get(bool) else "lazy"
        self.queue_kwargs = {
            "durable": queue_params["durable"].get(bool),
            "exclusive": queue_params["exclusive"].get(bool),
            "auto_delete": queue_params["auto_delete"].get(bool),
            "arguments": {"x-queue-mode": queue_mode},
        }
        max_items = queue_params["max_items"].get()
        if max_items:
            self.queue_kwargs["arguments"]["x-max-length"] = max_items

    def __decode(self, msg: str, decoder: json.JSONDecoder):
        """
        Decodes a JSON message with the given decoder. Returns the decoded object or
        None and logs an error.
        @param msg The message to decode
        @param decoder The decoder class to use for decoding
        """
        try:
            return json.loads(msg, cls=decoder)
        except Exception as e:
            self.logger.error(f"RabbitMQ consumer: error decoding message {msg}: {e}")
            return None

    def __provision_intel(self, channel, method_frame, header_frame, body):
        """
        Callback to be invoked by the Pika library whenever a new message `body` has
        been received from RabbitMQ on the intel queue.
        @param channel: pika.Channel The channel that was received on
        @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
        @param properties: pika.spec.BasicProperties Pika properties
        @param body: bytes The received message
        """
        msg = self.__decode(body, IntelDecoder)
        if msg:
            self.__provision("threatbus/intel", msg)
        self._channel.basic_ack(delivery_tag=method_frame.delivery_tag)

    def __provision_sighting(self, channel, method_frame, header_frame, body):
        """
        Callback to be invoked by the Pika library whenever a new message `body` has
        been received from RabbitMQ on the sighting queue.
        @param channel: pika.Channel The channel that was received on
        @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
        @param properties: pika.spec.BasicProperties Pika properties
        @param body: bytes The received message
        """
        msg = self.__decode(body, SightingDecoder)
        if msg:
            self.__provision("threatbus/sighting", msg)
        self._channel.basic_ack(delivery_tag=method_frame.delivery_tag)

    def __provision_snapshot_request(self, channel, method_frame, header_frame, body):
        """
        Callback to be invoked by the Pika library whenever a new message `body` has
        been received from RabbitMQ on the snapshot-request queue.
        @param channel: pika.Channel The channel that was received on
        @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
        @param properties: pika.spec.BasicProperties Pika properties
        @param body: bytes The received message
        """
        msg = self.__decode(body, SnapshotRequestDecoder)
        if msg:
            self.__provision("threatbus/snapshotrequest", msg)
        self._channel.basic_ack(delivery_tag=method_frame.delivery_tag)

    def __provision_snapshot_envelope(self, channel, method_frame, header_frame, body):
        """
        Callback to be invoked by the Pika library whenever a new message `body` has
        been received from RabbitMQ on the snapshot-envelope queue.
        @param channel: pika.Channel The channel that was received on
        @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
        @param properties: pika.spec.BasicProperties Pika properties
        @param body: bytes The received message
        """
        msg = self.__decode(body, SnapshotEnvelopeDecoder)
        if msg:
            self.__provision("threatbus/snapshotenvelope", msg)
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

        intel_cb = partial(
            self.on_exchange_declare_ok,
            userdata=(self.intel_exchange, self.intel_queue),
        )
        self._channel.exchange_declare(
            exchange=self.intel_exchange, exchange_type="fanout", callback=intel_cb
        )
        sighting_cb = partial(
            self.on_exchange_declare_ok,
            userdata=(self.sighting_exchange, self.sighting_queue),
        )
        self._channel.exchange_declare(
            exchange=self.sighting_exchange,
            exchange_type="fanout",
            callback=sighting_cb,
        )
        snapshotrequest_cb = partial(
            self.on_exchange_declare_ok,
            userdata=(self.snapshot_request_exchange, self.snapshot_request_queue),
        )
        self._channel.exchange_declare(
            exchange=self.snapshot_request_exchange,
            exchange_type="fanout",
            callback=snapshotrequest_cb,
        )
        snapshotenvelope_cb = partial(
            self.on_exchange_declare_ok,
            userdata=(self.snapshot_envelope_exchange, self.snapshot_envelope_queue),
        )
        self._channel.exchange_declare(
            exchange=self.snapshot_envelope_exchange,
            exchange_type="fanout",
            callback=snapshotenvelope_cb,
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

    def on_exchange_declare_ok(self, _frame, userdata: Tuple[str, str]):
        """
        Invoked as callback from exchange_declare. See self.on_channel_open.
        Issues declaration of a queue.
        @param _frame Unused pika response
        @param userdata A tuple of exchange_name and queue_name. The exchange with the given name was created, hence this method is invoked. The queue name should be created.
        """
        cb = partial(self.on_queue_declare_ok, userdata=userdata)
        self._channel.queue_declare(queue=userdata[1], callback=cb)

    def on_queue_declare_ok(self, _frame, userdata: Tuple[str, str]):
        """
        Inspects the given userdata (exchange_name, queue_name) and binds the queue to the exchange.
        @param _frame Unused pika response
        @param userdata A tuple of exchange_name and queue_name. Both have been created, hence this method is invoked.
        """
        cb = partial(self.on_queue_bind_ok, userdata=userdata[1])
        self._channel.queue_bind(exchange=userdata[0], queue=userdata[1], callback=cb)

    def on_queue_bind_ok(self, _frame, userdata: str):
        """
        Inspects the given userdata (exchange_name, queue_name) and binds the queue to the exchange.
        @param _frame Unused pika response
        @param userdata The name of the bound queue queue_name
        """
        callbacks_by_type = {
            self.intel_queue: self.__provision_intel,
            self.sighting_queue: self.__provision_sighting,
            self.snapshot_request_queue: self.__provision_snapshot_request,
            self.snapshot_envelope_queue: self.__provision_snapshot_envelope,
        }
        self.consumers.append(
            self._channel.basic_consume(userdata, callbacks_by_type[userdata])
        )

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
