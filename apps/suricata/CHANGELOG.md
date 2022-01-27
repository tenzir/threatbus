# Changelog

This changelog documents all notable user-facing changes of
`suricata-threatbus`.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 Features
- 🧬 Experimental Features
- ⚠️ Changes
- ⚡️ Breaking Changes
- 🐞 Bug Fixes

## [2022.01.27]

No user-facing changes.

## [2021.12.16]

No user-facing changes.

## [2021.11.22]

No user-facing changes.

## [2021.11.18]

No user-facing changes.

## [2021.09.30]

No user-facing changes.

## [2021.08.26]

- ⚠️ `suricata-threatbus` now depends on version 3.0 of `stix2` package.
  [#162](https://github.com/tenzir/threatbus/pull/162)

## [2021.07.29]

- ⚠️ The Dockerfile of `suricata-threatbus` has moved to the repository toplevel
  and now installs Threat Bus from source. This way, the Docker build always
  uses the `latest` Threat Bus sources, instead of the latest version from PyPI.
  [#141](https://github.com/tenzir/threatbus/pull/141)

- 🐞 `suricata-threatbus` now implements the new zmq management protocol of the
  `threatbus-zmq-app` plugin. The app now simply re-uses the Threat Bus hostname
  as it is configured in the users `config.yaml` and appends the port
  specifications for `pub` and `sub` communication that it receives as part of
  the subscription success response.
  [#140](https://github.com/tenzir/threatbus/pull/140)

- 🎁 We now release a pre-built Docker image for `suricata-threatbus` together
  with our future Threat Bus releases.
  [#137](https://github.com/tenzir/threatbus/pull/137)

- ⚠️ `suricata-threatbus` now uses
  [Dynaconf](https://github.com/rochacbruno/dynaconf) for configuration
  management. Configuration via a config file works exactly as it has worked
  before. Users can provide a path to the config file using the `-c` option.
  `suricata-threatbus` now considers files named `config.yaml` and `config.yml`
  as default configs if located in the same directory. Additionally,
  `suricata-threatbus` now supports configration via environment variables and
  `.dotenv`. Env vars need to be prefixed with `SURICATA_THREATBUS_` to be
  respected and always take precedence over values in config files.
  [#133](https://github.com/tenzir/threatbus/pull/133)

## [2021.06.24]

- 🎁 `suricata-threatbus` has come to life. This stand-alone application
  connects to Threat Bus via ZeroMQ and bridges the gap between Threat Bus and
  [Suricata](https://suricata.io/). `suricata-threatbus` maintains a custom
  rule file for Suricata to read from. That allows users users to sync their
  Suricata rules from other Threat Bus-connected tools, such as OpenCTI, with
  their Suricata IDS installations.
  [#131](https://github.com/tenzir/threatbus/pull/131)

[2021.06.24]: https://github.com/tenzir/threatbus/releases/tag/2021.06.24
[2021.07.29]: https://github.com/tenzir/threatbus/releases/tag/2021.07.29
[2021.08.26]: https://github.com/tenzir/threatbus/releases/tag/2021.08.26
[2021.09.30]: https://github.com/tenzir/threatbus/releases/tag/2021.09.30
[2021.11.18]: https://github.com/tenzir/threatbus/releases/tag/2021.11.18
[2021.11.22]: https://github.com/tenzir/threatbus/releases/tag/2021.11.22
[2021.12.16]: https://github.com/tenzir/threatbus/releases/tag/2021.12.16
[2022.01.27]: https://github.com/tenzir/threatbus/releases/tag/2022.01.27
