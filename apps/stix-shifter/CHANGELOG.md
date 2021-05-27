# Changelog

This changelog documents all notable user-facing changes of
`stix-shifter-threatbus`.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 Features
- 🧬 Experimental Features
- ⚠️ Changes
- ⚡️ Breaking Changes
- 🐞 Bug Fixes

<!-- ## Unreleased -->

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
