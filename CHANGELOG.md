# Changelog

This changelog documents all notable user-facing changes of Threat Bus.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 feature
- 🧬 experimental feature
- ⚠️ change
- 🐞 bugfix

## Unreleased

- 🎁 The `zmq-app` and `zeek` plugins now use the Unix select system call for
  improved performance during message passing. Both plugins forward messages a
  lot faster to subscribers than before.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- 🎁 Threat Bus now has a controlled shutdown. Pressing ctrl+c first shuts down
  backbone plugins, then app plugins, and lastly Threat Bus itself.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- ⚠️ There exists a new base class for implement plugin-threads. Plugin
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
