# Threat-Bus

The **Threat-Bus** (`threat-bus`) autonomously performs routine task of an
incident response team. The project is plugin-based and can be easily extended.

## Development Installation

```
virtualenv venv
source venv/bin/activate
pip install --editable .
pip install --editable plugins/<desired-plugins>
```

## Plugin Configuration & Extension

A plugin must define a `setup.py`. When the plugin is installed and should be
used by `threatbus`, you must add a section to the `config.yaml`. That section
is named after the name in the entrypoint declaration of the plugin's `setup.py`
file. Furthermore, you should adhere to the [plugin naming conventions](https://pluggy.readthedocs.io/en/latest/#a-complete-example)
and always prefix your plugin name with `threatbus-`.

Example:

- plugin folder structure:
  ```sh
  plugins
  └──threatbus-myplugin
     ├── setup.py
     └── threatbus_myplugin.py
  ```
- `setup.py`
  ```py
  from setuptools import setup
  setup(
    name="threatbus-myplugin",
    install_requires="threatbus",
    entry_points={"threatbus": ["myplugin = threatbus_myplugin"]},
    py_modules=["threatbus_myplugin"],
  )
  ```
- `config.yaml` entry for `threatbus`
  ```yaml
  ...
  plugins:
    myplugin:
      - this
      - is
      - plugin specific
  ```

## License

Copyright (c) Tenzir GmbH
All rights reserved.

[misp]: https://github.com/misp/misp
[vast]: https://github.com/vast-io/vast
[broker]: https://github.com/zeek/broker
[tenzir]: https://docs.tenzir.com
[zeek]: https://www.zeek.org
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration
