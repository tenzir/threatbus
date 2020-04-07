Threat Bus to VAST Bridge
=========================

Threat Bus is a publish-subscribe broker for threat intelligence. It is expected
that applications register themselves at the bus. Since vast cannot do so on its
own (yet), the `vast-bridge.py` is used for that purpose.

The bridge provides a thin layer around the PyVAST CLI bindings. It facilitates
message exchange between Threat Bus and a vast instance.

## Setup

- Install the PyVAST CLI bindings. See [github.com/tenzir/vast/README.md](https://github.com/tenzir/vast/blob/master/pyvast/)
- Install python bindings for ZeroMQ

```sh
virtualenv --system-site-packages venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

The bridge gets configured via command line arguments and flags. Start the
bridge as follows.

```sh
./vast-bridge --vast-binary=/opt/tenzir/bin/vast --vast=localhost:42000 --threatbus=localhost:13370
```