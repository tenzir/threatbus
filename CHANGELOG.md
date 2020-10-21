# Changelog

This changelog documents all notable user-facing changes of Threat Bus.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 feature
- 🧬 experimental feature
- ⚠️ change
- 🐞 bugfix

## Unreleased

- 🎁 The MISP plugin now works without a valid PyMISP API connection. If omitted in the configuration, the plugin can still receive indicators via ZeroMQ or Kafka, but it cannot report back sightings or request snapshots.
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
