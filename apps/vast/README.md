Threat Bus to VAST Bridge
=========================

Threat Bus is a publish-subscribe broker for threat intelligence. It is expected
that applications register themselves at the bus. Since VAST cannot do so on its
own (yet), `vast-bridge.py` implements that functionality in the meantime.

The bridge provides a thin layer around 
[PyVAST](https://docs.tenzir.com/vast/python-bindings/overview), VAST's Python
CLI bindings. It facilitates message exchange between Threat Bus and a VAST
instance.

## Setup

- Install the `requirements.txt` for the VAST wrapper script

```sh
virtualenv --system-site-packages venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Quick Start

The bridge gets configured via command line arguments and flags. Inspect the
command help as follows.

```sh
./vast-bridge --help
```

Startup with debug logging and customized endpoints for Threat Bus and VAST.

```sh
./vast-bridge --vast-binary=/opt/tenzir/bin/vast --vast=localhost:42000 --threatbus=localhost:13370 --loglevel=DEBUG
```

Request an intelligence snapshot of the past 50 days.

```sh
./vast-bridge.py --snapshot=50
```

## Bridge Features

This section explains the most important features of the `vast-bridge` and the
CLI toggles to enable them.

### IoC Matching

VAST can match IoCs either live (pro-feature) or retrospectively via the means
of usual queries.

#### Live Matching

VAST's
[live matching](https://docs.tenzir.com/vast/features/threat-intel-matching)
works as
[continuous query](https://docs.tenzir.com/vast/cli/vast/export/#documentation).
The `vast-bridge` subscribes to those continuous query results and reports all
new IoC matches from VAST to Threat Bus as `Sightings`.

The live matching is the default mode of operation for the `vast-bridge`. Note
that the VAST node must support this feature.

#### Retro Matching

The `vast-bridge` supports retro matching via the command line toggle
`--retro-match`. When this toggle is used, the bridge transforms IoCs from
Threat Bus to valid VAST queries, instead of feeding the IoCs to a live matcher.

Each result from an IoC query is treated as `Sighting` of that IoC and reported
back to Threat Bus.

### Sighting Context Transformation

The bridge provides a command line option to invoke another program for parsing
Sighting context data.

A `Sighting` object is structured as follows:

```yaml
{
  "ts": "2020-09-04 11:21:13.663164",
  "reference": "threatbus__86",
  "ioc": "foobar.com",
  "context": {
    ...
  }
```

The `context` field can contain arbitrary data. For example, retro matches from
VAST contain the full query result in the context field (like a Suricata EVE
entry or a Zeek conn.log entry).

Use the CLI toggle `--transform-context "cmd args" to transform the `context`
object via some command line tool. For example, pass the `context` object to
[DCSO/fever](https://github.com/DCSO/fever) `alertify`:

```
apps/vast/vast-bridge.py --retro-match --transform-context "fever alertify --alert-prefix VAST-RETRO --extra-key vast-ioc --ioc %ioc"
```

Note that the `cmd` string passed to `--transform-context` is treated as
template string. The placeholder `%ioc` is replaced with the contents of the
actually matched IoC.

### Custom Sinks for Sightings

The `vast-bridge` offers to send Sighting `context` to a configurable `sink`
_instead_ of reporting them back to Threat Bus. This can be configured via the
`--sink` parameter. The special placeholder `STDOUT` can be used to print the
Sighting context to `STDOUT`. Example:

```
apps/vast/vast-bridge.py --sink stdout
```

A custom sink is useful to forward `Sightings` to another process, like
`syslog`, or forward STDOUT via a UNIX pipe. Note that it may be desirable to
disable logging in that case (`--loglevel NOTSET`).

Note that only the `context` field is printed, and not the object structure of
the `Sighting`. The `Sighting` itself is a Threat Bus internal format and most
likely not usable for most applications.
