# Changelog

This changelog documents all notable user-facing changes of `pyvast-threatbus`.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 Features
- 🧬 Experimental Features
- ⚠️ Changes
- ⚡️ Breaking Changes
- 🐞 Bug Fixes

## Unreleased

- ⚠️ The metric for indicator query time now only reflects the actual time spent
  querying VAST and does not regard unstarted VAST queries any longer.
  [#145](https://github.com/tenzir/threatbus/pull/145)

- ⚠️ Metrics sent by `pyvast-threatbus` used the short hostname as given by
  `socket.gethostname()`. This has been changed to use `socket.getfqdn()`.
  [#144](https://github.com/tenzir/threatbus/pull/144)

- ⚠️ The Dockerfile of `pyvast-threatbus` has moved to the repository toplevel
  and now installs Threat Bus from source. This way, the Docker build always
  uses the `latest` Threat Bus sources, instead of the latest version from PyPI.
  [#141](https://github.com/tenzir/threatbus/pull/141)

- 🐞 `pyvast-threatbus` now implements the new zmq management protocol of the
  `threatbus-zmq-app` plugin. The app now simply re-uses the Threat Bus hostname
  as it is configured in the users `config.yaml` and appends the port
  specifications for `pub` and `sub` communication that it receives as part of
  the subscription success response.
  [#140](https://github.com/tenzir/threatbus/pull/140)

- 🐞 The metrics value serialization in `pyvast-threatbus` contained spaces in
  the fields of the measurements, which is not valid according to the
  [line protocol spec](https://docs.influxdata.com/influxdb/v2.0/reference/syntax/line-protocol/)
  and caused the measurement to be rejected. We fixed the format to ensure all
  fields are separated by commas.
  [#136](https://github.com/tenzir/threatbus/pull/136)

- ⚠️ `pyvast-threatbus` now uses
  [Dynaconf](https://github.com/rochacbruno/dynaconf) for configuration
  management. Configuration via a config file works exactly as it has worked
  before. Users can provide a path to the config file using the `-c` option.
  `pyvast-threatbus` now considers files named `config.yaml` and `config.yml` as
  default configs if located in the same directory. Additionally,
  `pyvast-threatbus` now supports configration via environment variables and
  `.dotenv`. Env vars need to be prefixed with `PYVAST_THREATBUS_` to be
  respected and always take precedence over values in config files.
  [#133](https://github.com/tenzir/threatbus/pull/133)

## [2021.06.24]

- ⚡️ `pyvast-threatbus` now uses point queries over substring queries for
  URI indicators, because such queries are much faster. This may result
  in less matches than before. E.g., a URI indicator `tenzir.com` that
  used to match `docs.tenzir.com` as well as `https://tenzir.com` now
  only matches exactly the indicator.
  [#130](https://github.com/tenzir/threatbus/pull/130)

- 🎁 `pyvast-threatbus` now collects metrics about received indicators that are
  about to be matched retrospectively against VAST. The new metric is called
  `retro_match_backlog` and allows users to determine if a backlog is
  building up. A backlog builds when `pyvast-threatbus` hits the
  user-configured limit of max backgroud tasks while at the same time VAST
  responds slowly to the issued queries.
  [#129](https://github.com/tenzir/threatbus/pull/129)

- 🎁 `pyvast-threatbus` now comes with its own Dockerfile. Pre-built images are
  available on [Dockerhub](https://hub.docker.com/r/tenzir/pyvast-threatbus).
  [#126](https://github.com/tenzir/threatbus/pull/126)

## [2021.05.27]

- ⚠️ All Threat Bus apps that connect via ZeroMQ like `pyvast-threatbus`. now
  shutdown gracefully and do not longer print a stack trace when receiving any
  stop signal.
  [#118](https://github.com/tenzir/threatbus/pull/118)

- ⚠️ The `-c` / `--config` parameter is now explicitly required to start
  `pyvast-threatbus`. Starting without it will print a helpful error message.
  [#119](https://github.com/tenzir/threatbus/pull/119)

- ⚠️ `pyvast-threatbus` now uses the timestamp of retro- & live-matches to set
  the `last_seen` property of STIX-2 Sightings, instead of setting the `created`
  timestamp. The `created` timestamp now always refers to the actual creation
  time of the sightings.
  [#117](https://github.com/tenzir/threatbus/pull/117)


## [2021.04.29]

- 🐞 We fixed an unhandled exception in the post-processing of sighting context
  data for both retro- and live-matched sightings. The bug was introduced with
  the STIX-2 rewrite and effectively rendered both the `transform_context` and
  `sink` options unusable.
  [#112](https://github.com/tenzir/threatbus/pull/112)

- 🎁 `pyvast-threatbus` now supports a new config option to set timeouts for
  VAST retro-queries: `retro_match_timeout`. Pending queries are killed upon
  timeout. VAST results that were exported before the timeout hit are still
  reported as valid Sightings.
  [#110](https://github.com/tenzir/threatbus/pull/110)

- ⚠️ VAST's proprietary
  [Threat Intel Matching](https://docs.tenzir.com/vast/features/threat-intel-matching)
  feature was rewritten as a VAST plugin. `pyvast-threatbus` now works with the
  changed command line interface.
  [#109](https://github.com/tenzir/threatbus/pull/109)

- 🐞 We fixed a bug where VAST matcher results where passed to the wrong mapping
  function after being retrieved from VAST.
  [#109](https://github.com/tenzir/threatbus/pull/109)



## [2021.03.25]

- 🎁 `pyvast-threatbus` now supports the
  [STIX-2 (version 2.1)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
  standard for
  [Indicators](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_muftrcpnf89v)
  and [Sightings](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_a795guqsap3r).
  The app converts STIX-2 Indicators on best-effort basis to both VAST queries
  and VAST matcher IoCs to support both retro- and live-matching. Likewise,
  `pyvast-threatbus` converts VAST query results as well as VAST matcher
  sightings to valid STIX-2 Sightings before publishing them on Threat Bus
  topics.
  [#105](https://github.com/tenzir/threatbus/pull/105)

- ⚠️ The retro-matching now applies a strict equality comparison when mapping
  IoCs to VAST queries. Prior to this change `pyvast-threatbus` used substring
  search, which came at heavy runtime costs when issuing hundreds of queries
  per second.
  [#104](https://github.com/tenzir/threatbus/pull/104)

## [2021.02.24]

- 🐞 Users can now run retro-queries with an unbounded number of results against
  VAST by setting the `retro_match_max_events` parameter to `0`.
  [#98](https://github.com/tenzir/threatbus/pull/98)

- ⚠️ Users now can use both, retro-matching and live-matching with VAST
  simultaneously for any given IoC. On the flip side, there is no longer a
  default mode of operation. To use live-matching, users now must specifically
  configure it via setting `live_match: true` in their `config.yaml` file.
  [#95](https://github.com/tenzir/threatbus/pull/95)

- ⚠️ `pyvast-threatbus` drops support to unflatten JSON that it receives from
  `vast export` because VAST can now return unflattened JSON
  [by default](https://github.com/tenzir/vast/pull/1257).
  [#92](https://github.com/tenzir/threatbus/pull/92)

## [2020.12.16]

- 🎁 `pyvast-threatbus` now supports basic metric collection. It stores metrics
  in [influx line protocol](https://docs.influxdata.com/influxdb/v2.0/reference/syntax/line-protocol/)
  syntax in a configurable file on disk.
  [#85](https://github.com/tenzir/threatbus/pull/85)

- ⚠️ `pyvast-threatbus` cannot be started with command line arguments anymore.
  From now on, the application only supports one option, `-c`, to pass a config
  file.
  [#85](https://github.com/tenzir/threatbus/pull/85)

- 🎁 `pyvast-threatbus` now uses the Threat Bus `logger` module. Users can
  configure logging the same way as in Threat Bus, via a `logging` section in
  the `config.yaml` file.
  [#80](https://github.com/tenzir/threatbus/pull/80)

## [2020.11.26]

- 🐞 `pyvast-threatbus` escapes backslashes and quotes in IoCs before it queries
  VAST.
  [#74](https://github.com/tenzir/threatbus/pull/74)

- 🎁 `pyvast-threatbus` now uses asynchronous background tasks to query VAST
  concurrently. VAST queries were executed sequentially prior to this change.
  This boosts the performance by the factor of allowed concurrent background
  tasks. Users can control the maximum number of concurrent background tasks
  with the new `max-background-tasks` configuration option.
  [#61](https://github.com/tenzir/threatbus/pull/61)

- 🎁 The Python app to connect [VAST](https://github.com/tenzir/vast) with
  Threat Bus is now packaged and published on [PyPI](https://pypi.org/). You can
  install the package via `pip install pyvast-threatbus`.
  [#63](https://github.com/tenzir/threatbus/pull/63)

[2020.11.26]: https://github.com/tenzir/threatbus/releases/tag/2020.11.26
[2020.12.16]: https://github.com/tenzir/threatbus/releases/tag/2020.12.16
[2021.02.24]: https://github.com/tenzir/threatbus/releases/tag/2021.02.24
[2021.03.25]: https://github.com/tenzir/threatbus/releases/tag/2021.03.25
[2021.04.29]: https://github.com/tenzir/threatbus/releases/tag/2021.04.29
[2021.05.27]: https://github.com/tenzir/threatbus/releases/tag/2021.05.27
[2021.06.24]: https://github.com/tenzir/threatbus/releases/tag/2021.06.24
