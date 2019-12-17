import argparse
import confuse
import logging
import pluggy
from threatbus import appspecs, backbonespecs, logger


class ThreatBus:
    def __init__(self, backbones, apps, config):
        self.backbones, self.apps = backbones, apps
        self.config = config
        self.logger = logger.setup(config["logging"], "threatbus")
        self.run()
        self.receive()

    def run(self):
        self.backbones.run(config=self.config['plugins']['backbones'], logging=self.config['logging'])
        self.apps.run(config=self.config['plugins']['apps'], logging=self.config['logging'])

    def receive(self):
        for msg in self.apps.threatbus_receive():
            self.logger.info(msg)


def validate_config(config):
    c = config["logging"]["console"].get(bool)
    f = config["logging"]["file"].get(bool)
    config["logging"]["console_verbosity"].get(str)
    config["logging"]["file_verbosity"].get(str)
    config["logging"]["filename"].get(str)


def main():
    backbones = pluggy.PluginManager("threatbus.backbone")
    backbones.add_hookspecs(backbonespecs)
    backbones.load_setuptools_entrypoints("threatbus.backbone")

    apps = pluggy.PluginManager("threatbus.app")
    apps.add_hookspecs(appspecs)
    apps.load_setuptools_entrypoints("threatbus.app")

    config = confuse.Configuration("threatbus")
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="path to a configuration file")
    args = parser.parse_args()
    config.set_args(args)
    if args.config:
        config.set_file(args.config)

    try:
        validate_config(config)
    except Exception as e:
        raise ValueError("Invalid config: {}".format(str(e)))
    bus = ThreatBus(backbones.hook, apps.hook, config)


if __name__ == "__main__":
    main()
