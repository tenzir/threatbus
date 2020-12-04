Threat Bus Systemd Unit
=======================

This folder provides `systemd` service units to run Threat Bus and
`pyvast-threatbus` as system services. The services are sandboxed and run with
limited privileges.

## Prepare the Host System

Please note that all subsequent commands require `root` privileges. The services
run with the privileges of a user and group called `threatbus`. You can create
them as follows.

```bash
useradd --system --user-group threatbus
```

Make sure that you don't grant any special rights to this user, i.e., do not
enable `sudo` or other privileged commands for this user.

#### Log-Directories

This section explains how to set up log-directories for file-logging. Skip the
following instructions if you configure your applications to use console-logging.

```bash
mkdir -p /var/log/threatbus /var/log/pyvast-threatbus
chown -R threatbus:threatbus /var/log/threatbus /var/log/pyvast-threatbus
```

For Threat Bus, find the logging config at the top of your Threat Bus
configuration file and change it to use the new directory:

```yaml
logging:
  console: false
  console_verbosity: INFO
  file: true
  file_verbosity: DEBUG
  filename: /var/log/threatbus/threatbus.log
```

For `pyvast-threatbus`, simply pipe the logput into a file.

## Usage

Before you begin, find the line beginning with `ExecStart=` at the very bottom
of the `[Service]` section in the unit file. Depending on your installation path
you might need to change the location of the `threatbus` and `pyvast-threatbus`
executable packages and configuration files.

- Threat Bus
  ```bash
  ExecStart=/path/to/threatbus --config=/path/to/threatbus/config.yaml
  ```

- `pyvast-threabus`
  ```bash
  ExecStart=/path/to/pyvast-threatbus --config=/path/to/pyvast-threatbus/config.yaml
  ```

Then copy (or symlink) the unit file to `/etc/systemd/system`.

```bash
systemctl link "$PWD/threatbus.service"
systemctl link "$PWD/pyvast-threatbus.service"
```

To have the services start up automatically with system boot, you can `enable`
them via `systemd`. Otherwise, just `start` it to run it immediately.

```bash
systemctl enable threatbus
systemctl start threatbus
systemctl enable pyvast-threatbus
systemctl start pyvast-threatbus
```
