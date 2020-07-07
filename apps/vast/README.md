Threat Bus to VAST Bridge
=========================

Threat Bus is a publish-subscribe broker for threat intelligence. It is expected
that applications register themselves at the bus. Since VAST cannot do so on its
own (yet), `vast-bridge.py` implements that functionality in the meantime.

The bridge provides a thin layer around 
[PyVAST](https://docs.tenzir.com/vast/python-bindings/overview), VAST's Python CLI bindings. It facilitates
message exchange between Threat Bus and a VAST instance.

## Setup

- [Install PyVAST](https://docs.tenzir.com/vast/python-bindings/installation)
- Install the `requirements.txt` for the VAST wrapper script

```sh
virtualenv --system-site-packages venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

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