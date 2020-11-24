# Changelog

This changelog documents all notable user-facing changes of `pyvast-threatbus`.

Every entry has a category for which we use the following visual abbreviations:

- 🎁 feature
- 🧬 experimental feature
- ⚠️ change
- ⚡️ breaking change
- 🐞 bugfix

## Unreleased

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

