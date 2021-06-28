# Changelog

This changelog documents all notable user-facing changes of
`suricata-threatbus`.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 Features
- 🧬 Experimental Features
- ⚠️ Changes
- ⚡️ Breaking Changes
- 🐞 Bug Fixes

## Unreleased

- 🎁 We now release a pre-built Docker image for `suricata-threatbus` together
  with our future Threat Bus releases.
  [#137](https://github.com/tenzir/threatbus/pull/137)

## [2021.06.24]

- 🎁 `suricata-threatbus` has come to life. This stand-alone application
  connects to Threat Bus via ZeroMQ and bridges the gap between Threat Bus and
  [Suricata](https://suricata.io/). `suricata-threatbus` maintains a custom
  rule file for Suricata to read from. That allows users users to sync their
  Suricata rules from other Threat Bus-connected tools, such as OpenCTI, with
  their Suricata IDS installations.
  [#131](https://github.com/tenzir/threatbus/pull/131)

[2021.06.24]: https://github.com/tenzir/threatbus/releases/tag/2021.06.24
