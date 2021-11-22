# Changelog

This changelog documents all notable user-facing changes of Threat Bus.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 Features
- ⚠️ Changes
- ⚡️ Breaking Changes
- 🧬 Experimental Features
- 🐞 Bug Fixes

## [2021.11.22]

- 🐞 `vast-threatbus` no longer fails to check for the availability of low
  priority queries.
  [#173](https://github.com/tenzir/threatbus/pull/173)

## [2021.11.18]

- ⚠️ `vast-threatbus` now issues low priority queries if those are supported by
  the version of VAST.
  [#171](https://github.com/tenzir/threatbus/pull/171)

## [2021.09.30]

- ⚠️  `threatbus` now depends on version 1.0 of `pluggy`.

## [2021.08.26]

- ⚡️ The `threatbus-zmq-app` package has been renamed to `threatbus-zmq`, to
  address some limitations in the configuration framework.
  [#157](https://github.com/tenzir/threatbus/pull/157)

- 🐞 Fixed config validation for the 'apps.misp.api' setting.
  [#161](https://github.com/tenzir/threatbus/pull/161)

- ⚠️ `vast-threatbus` now depends on version 3.0 of `stix2` package.
  [#162](https://github.com/tenzir/threatbus/pull/162)

## [2021.07.29]

- 🐞 Threatbus now only attempts to load plugins that are explicitly
  listed in the config file.
  [#150](https://github.com/tenzir/threatbus/pull/140)

- 🎁 Many configuration options for `threatbus` and `pyvast-threatbus` now have
  default values. See the example configs for a detailed list.
  [#150](https://github.com/tenzir/threatbus/pull/140)

- 🐞 The content and format of the `threatbus-zmq-app` plugin's subscription
  success response has changed. Prior to this change, the plugin used to respond
  with an endpoint in the `host:port` format, which contained a wrong hostname
  (e.g., `0.0.0.0` instead of a publicly reachable topic).
  From now on, the plugin returns only the ports for `pub` and `sub`
  communication and leaves it to the subscribing app to connect with the right
  host/IP.
  [#140](https://github.com/tenzir/threatbus/pull/140)

- ⚠️ Threat Bus now uses [Dynaconf](https://github.com/rochacbruno/dynaconf) for
  configuration management. Configuration via a config file works exactly as it
  has worked before. Users can provide a path to the config file using the `-c`
  option. Threat Bus now considers files named `config.yaml` and `config.yml` as
  default configs if located in the same directory. Additionally, Threat Bus now
  supports configration via environment variables and `.dotenv`. Env vars need
  to be prefixed with `THREATBUS_` to be respected and always take precedence
  over values in config files.
  [#133](https://github.com/tenzir/threatbus/pull/133)

## [2021.06.24]

- ⚠️ The official [tenzir/threatbus](https://hub.docker.com/r/tenzir/threatbus)
  Docker image now uses Debian:Bullseye as
  [base image](https://hub.docker.com/_/debian) and uses the Debian-maintained
  Broker libraries to enable communication with [Zeek](https://zeek.org/).
  [#132](https://github.com/tenzir/threatbus/pull/132)

- ⚠️  The Threat Bus community chat moved from Gitter to Slack. 
  [Join us](http://slack.tenzir.com) in the `#threatbus` channel for
  interactive discussions.
  [#123](https://github.com/tenzir/threatbus/pull/123)

## [2021.05.27]

- 🎁 Threat Bus now supports subscriptions for multiple topics. The
  `zmq-app-plugin` implements those multi-topic subscriptions in a
  backwards-compatible way. Subscribers benefit from this change, as they only
  get assigned a single point-to-point topic for their subscription, instead of
  one point-to-point topic for every subscribed Threat Bus topic.
  [#120](https://github.com/tenzir/threatbus/pull/120)

- ⚠️ The `-c` / `--config` parameter is now explicitly required to start
  Threat Bus. Starting without it will print a helpful error message.
  [#119](https://github.com/tenzir/threatbus/pull/119)

- 🎁 We now provide a simple asyncio
  [template](https://github.com/tenzir/threatbus/tree/master/apps/zmq-app-template)
  for writing applications that connect to Threat Bus via ZeroMQ.
  [#118](https://github.com/tenzir/threatbus/pull/118)

- ⚠️ The `threatbus-zeek` plugin now uses the timestamp of Zeek intel matches to
  set the `last_seen` property of resulting STIX-2 Sightings, instead of setting
  the `created` timestamp. The `created` timestamp now always refers to the
  actual creation time of the sightings.
  [#117](https://github.com/tenzir/threatbus/pull/117)


## [2021.04.29]

- 🐞 We fixed a bug in the ZeroMQ app plugin that threw an exception upon
  receiving `SnapshotRequests`.
  [#116](https://github.com/tenzir/threatbus/pull/116)

- ⚠️ The Threat Bus community chat moved from Element to Gitter. Join us at
  [gitter.im/tenzir/threatbus](https://gitter.im/tenzir/threatbus) or via
  Matrix at `#tenzir_threatbus:gitter.im`.
  [#113](https://github.com/tenzir/threatbus/pull/113)

## [2021.03.25]

- 🎁 The CIFv3 plugin now supports the
  [STIX-2 (version 2.1)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
  standard for
  [Indicators](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_muftrcpnf89v).
  The plugin converts STIX-2 Indicators on best-effort basis to CIFv3
  indicators before forwarding them to the configured CIF endpoint.
  [#106](https://github.com/tenzir/threatbus/pull/106)

- 🐞 We fixed a bug in the routing logic for SnapshotRequests. Apps can now
  request snapshots as expected for all `stix2`-prefixed topics.
  [#103](https://github.com/tenzir/threatbus/pull/103)

- 🎁 The Zeek plugin now supports the
  [STIX-2 (version 2.1)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
  standard for
  [Indicators](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_muftrcpnf89v)
  and [Sightings](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_a795guqsap3r).
  The plugin converts STIX-2 Indicators on best-effort basis to
  [Zeek Intel items](https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type)
  before forwarding them to Zeek. Likewise, the plugin converts Zeek sightings
  to valid STIX-2 Sightings before publishing them on Threat Bus topics.
  [#103](https://github.com/tenzir/threatbus/pull/103)

- 🎁 The MISP plugin now supports the
  [STIX-2 (version 2.1)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
  standard for
  [Indicators](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_muftrcpnf89v)
  and [Sightings](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_a795guqsap3r).
  The plugin converts MISP attributes to valid STIX-2 Indicators on best-effort
  basis before publishing them on Threat Bus topics. Likewise, the plugin
  converts STIX-2 Sightings to MISP sightings before sending them the MISP.
  [#102](https://github.com/tenzir/threatbus/pull/102)

- 🐞 We fixed a bug in the JSON (de-)serialization logic for `SnapshotEnvelope`s
  and `SnapshotRequest`s that lead to a malformed `type` field in the JSON
  representations of both types.
  [#102](https://github.com/tenzir/threatbus/pull/102)


## [2021.02.24]

- 🎁 The MISP plugin now uses
  [extra dependencies](https://www.python.org/dev/peps/pep-0508/#extras).
  Users can now chose the wanted dependencies during installation by running
  `pip install threatbus-misp[zmq]` to install the ZeroMQ dependency, or
  `pip install threatbus-misp[kafka]` to install the Kafka dependency. The
  plugin throws a fatal error if none of these dependencies is installed and
  exits immediately.
  [#99](https://github.com/tenzir/threatbus/pull/99)

- 🎁 The RabbitMQ backbone plugin, the In-memory backbone plugins, and the
  Zmq-app plugin now support the
  [STIX-2 (version 2.1)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
  standard for
  [Indicators](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_muftrcpnf89v)
  and [Sightings](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_a795guqsap3r).
  [#97](https://github.com/tenzir/threatbus/pull/97)

- ⚡️ Threat Bus now uses
  [STIX-2 (version 2.1)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
  as internal transport format for
  [Indicators](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_muftrcpnf89v)
  and [Sightings](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_a795guqsap3r).
  App-plugins now have to provide required mappings between the STIX-2 format
  and app-specific formats (e.g., the Zeek plugin needs to map STIX-2 to the
  Zeek intel format). The home-made types `threatbus.data.Sighting` and
  `threatbus.data.Indicator` are removed from the codebase.
  Plugins with versions earlier than 2021.02.24 are incompatible to the new
  Threat Bus version.
  [#97](https://github.com/tenzir/threatbus/pull/97)

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
[2021.02.24]: https://github.com/tenzir/threatbus/releases/tag/2021.02.24
[2021.03.25]: https://github.com/tenzir/threatbus/releases/tag/2021.03.25
[2021.04.29]: https://github.com/tenzir/threatbus/releases/tag/2021.04.29
[2021.05.27]: https://github.com/tenzir/threatbus/releases/tag/2021.05.27
[2021.06.24]: https://github.com/tenzir/threatbus/releases/tag/2021.06.24
[2021.07.29]: https://github.com/tenzir/threatbus/releases/tag/2021.07.29
[2021.08.26]: https://github.com/tenzir/threatbus/releases/tag/2021.08.26
[2021.09.30]: https://github.com/tenzir/threatbus/releases/tag/2021.09.30
[2021.11.18]: https://github.com/tenzir/threatbus/releases/tag/2021.11.18
[2021.11.22]: https://github.com/tenzir/threatbus/releases/tag/2021.11.22
