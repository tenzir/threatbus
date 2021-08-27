# Changelog

This changelog documents all notable user-facing changes of
`stix-shifter-threatbus`.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 Features
- 🧬 Experimental Features
- ⚠️ Changes
- ⚡️ Breaking Changes
- 🐞 Bug Fixes

## [2021.08.26]

- ⚠️ `stix-shifter-threatbus` now depends on version 3.0 of `stix2` package.
  [#162](https://github.com/tenzir/threatbus/pull/162)

## [2021.07.29]

- ⚠️ The Dockerfile of `stix-shifter-threatbus` has moved to the repository
  toplevel and now installs Threat Bus from source. This way, the Docker build
  always uses the `latest` Threat Bus sources, instead of the latest version
  from PyPI.
  [#141](https://github.com/tenzir/threatbus/pull/141)

- 🐞 `stix-shifter-threatbus` now implements the new zmq management protocol of
  the `threatbus-zmq-app` plugin. The app now simply re-uses the Threat Bus
  hostname as it is configured in the users `config.yaml` and appends the port
  specifications for `pub` and `sub` communication that it receives as part of
  the subscription success response.
  [#140](https://github.com/tenzir/threatbus/pull/140)

- ⚠️ `stix-shifter-threatbus` now uses
  [Dynaconf](https://github.com/rochacbruno/dynaconf) for configuration
  management. Configuration via a config file works exactly as it has worked
  before. Users can provide a path to the config file using the `-c` option.
  `stix-shifter-threatbus` now considers files named `config.yaml` and
  `config.yml` as default configs if located in the same directory.
  Additionally, `stix-shifter-threatbus` now supports configration via
  environment variables and `.dotenv`. Env vars need to be prefixed with
  `STIX_SHIFTER_THREATBUS_` to be respected and always take precedence over
  values in config files.
  [#133](https://github.com/tenzir/threatbus/pull/133)

## [2021.06.24]

- 🎁 `stix-shifter-threatbus` now comes with its own Dockerfile. Pre-built
  images are available on
  [Dockerhub](http://hub.docker.com/r/tenzir/stix-shifter-threatbus).
  [#126](https://github.com/tenzir/threatbus/pull/126)

- 🎁 `stix-shifter-threatbus` now reports back STIX-2 Sightings to Threat Bus.
  STIX-Shifter transmission results are first translated, using the respective
  native STIX-Shifter module's translation function. The resulting STIX-2.0
  bundles are then traversed to create sightings for every contained
  observation. These sightings are then finally returned to Threat Bus via
  ZeroMQ. The original observation objects are kept in each sighting's context
  data.
  [#125](https://github.com/tenzir/threatbus/pull/125)

## [2021.05.27]

- 🎁 `stix-shifter-threatbus` has come to life. This stand-alone application
  connects to Threat Bus via ZeroMQ and bridges the gap between Threat Bus and
  commercial security tools, like
  [IBM QRadar](https://www.ibm.com/security/security-intelligence/qradar) or
  [Splunk](https://www.splunk.com/). `stix-shifter-threatbus` uses
  [STIX-Shifter](https://github.com/opencybersecurityalliance/stix-shifter) to
  first translate STIX-2 Indicators to native queries for commercial tools and
  then execute these queries to log the results.
  [#118](https://github.com/tenzir/threatbus/pull/118)

[2021.05.27]: https://github.com/tenzir/threatbus/releases/tag/2021.05.27
[2021.06.24]: https://github.com/tenzir/threatbus/releases/tag/2021.06.24
[2021.07.29]: https://github.com/tenzir/threatbus/releases/tag/2021.07.29
[2021.08.26]: https://github.com/tenzir/threatbus/releases/tag/2021.08.26
