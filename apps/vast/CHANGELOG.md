# Changelog

This changelog documents all notable user-facing changes of `pyvast-threatbus`.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 feature
- 🧬 experimental feature
- ⚠️ change
- ⚡️ breaking change
- 🐞 bugfix

 <!-- ## Unreleased -->

## [2020.12.16]

- 🎁 `pyvast-threatbus` now uses the Threat Bus `logger` module. Users can
  configure logging the same way as in Threat Bus, via a `logging` section in
  the `config.yaml` file. The new configuration section and the `--loglevel`
  option are mutually exclusive.
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
