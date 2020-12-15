# Changelog

This changelog documents all notable user-facing changes of Threat Bus.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 feature
- 🧬 experimental feature
- ⚠️ change
- 🐞 bugfix

<!-- ## Unreleased -->

## [2020.12.16]

- 🎁 New systemd unit files are now available in the Threat Bus
  [repository](https://github.com/tenzir/threatbus/tree/master/threatbus)
  to run both Threat Bus and `pyvast-threatbus` as system services.
  [#77](https://github.com/tenzir/threatbus/pull/77)

## [2020.11.30]

- 🐞 The RabbitMQ backbone plugin ignored user-defined queue parameters, such as
  `durable` or `lazy` queues. It now respects such parameters again.
  [#76](https://github.com/tenzir/threatbus/pull/76)

## [2020.11.26]

- 🐞 The Zeek app did not perform an outbound connection to Threat Bus in
  cluster mode. Now the master peers with Threat Bus to establish a connection.
  [#68](https://github.com/tenzir/threatbus/pull/68)

- 🎁 The `zmq-app` and `zeek` plugins now use the Unix select system call for
  improved performance during message passing. The previous approach impacted
  the performance with a constant delay for every message and did not scale.
  The new approach saves at least that constant factor *per message*. For ZeroMQ
  publishing we observed a speedup of approximately factor 183 for 100k events.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- 🎁 The `rabbitmq` backbone plugin now uses an asynchronous
  [SelectConnection](https://pika.readthedocs.io/en/stable/modules/adapters/select.html)
  instead of a blocking one. We measured a speedup of approximately factor 1.2
  for 100k events.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- 🎁 Threat Bus now has a controlled shutdown. Pressing ctrl+c first shuts down
  backbone plugins, then app plugins, and lastly Threat Bus itself.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- ⚠️ There exists a new base class for implementing plugin-threads. Plugin
  developers should extend the new `StoppableWorker` for every plugin. Threat
  Bus and all plugins in this repository now implement that class.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- ⚠️ Threat Bus and all plugins now use
  [multiprocessing.JoinableQueue](https://docs.python.org/3.8/library/multiprocessing.html#multiprocessing.JoinableQueue)
  for message passing.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- 🎁 The `zmq-app` plugin now supports synchronous heartbeats. With heartbeats,
  both Threat Bus and the connected apps can mutually ensure that the connected
  party is still alive.
  [#58](https://github.com/tenzir/threatbus/pull/58)

## [2020.10.29]

- 🎁 The MISP plugin now works without a valid PyMISP API connection. If omitted
  in the configuration, the plugin can still receive indicators via ZeroMQ or
  Kafka, but it cannot report back sightings or request snapshots.
  [#55](https://github.com/tenzir/threatbus/pull/55)

- 🎁 The MISP plugin now supports a whitelist-filtering mechanism. Users can
  specify required properties of IoCs (MISP attributes) in the configuration
  file. The filter is implemented for IoCs that are received via ZeroMQ or Kafka
  as well as IoCs that are requested as part of a snapshot.
  [#49](https://github.com/tenzir/threatbus/pull/49)

- 🎁 The generic Threat Bus ZeroMQ application plugin has replaced the former
  VAST plugin. Any app that communicates via ZeroMQ can implement this plugin's
  protocol to connect with Threat Bus effortlessly.
  [#46](https://github.com/tenzir/threatbus/pull/46)


[2020.10.29]: https://github.com/tenzir/threatbus/releases/tag/2020.10.29
[2020.11.26]: https://github.com/tenzir/threatbus/releases/tag/2020.11.26
[2020.11.30]: https://github.com/tenzir/threatbus/releases/tag/2020.11.30
[2020.12.16]: https://github.com/tenzir/threatbus/releases/tag/2020.12.16
