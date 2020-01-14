Threat Bus MISP Plugin
======================

A Threat Bus plugin that facilitates communication to [MISP](https://www.misp-project.org/).

## Installation

```sh
pip install threatbus-misp
```

## Development Setup

Use the [dcso/MISP-dockerized](https://github.com/DCSO/MISP-dockerized) project to set up a local testing environment:

*Setup a MISP docker cluster*
```
git clone git@github.com:DCSO/MISP-dockerized.git
cd MISP-dockerized
make install
# follow the dialog...
```

*Edit the docker-compose.yaml*

```sh
cd current
vim docker-compose.yaml
```
Find the section `misp-server` in the yaml and add the following:

```yaml
misp-server:
    ...
    ports:
      - "50000:50000"
    ...
```

*Restart all those MISP services that changed*

```sh
make deploy
```

*Enable the ZMQ plugin in the MISP webview*

- Visit localhost:80
- login with your configured credentials
- Go to `Administration` -> `Server Settings & Maintenance` -> `Diagnostics Tab`
- Find the ZeroMQ plugin section and enable it

