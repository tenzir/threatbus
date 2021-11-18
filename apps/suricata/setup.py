#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    author="Tenzir",
    author_email="engineering@tenzir.com",
    classifiers=[
        # https://pypi.org/classifiers/
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: BSD License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
        "Topic :: Security",
        "Topic :: Software Development :: Object Brokering",
        "Topic :: System :: Distributed Computing",
    ],
    description="A simple ZMQ app to connect to Threat Bus and ingest indicators as Suricata rules via `suricatasc`",
    entry_points={
        "console_scripts": ["suricata-threatbus=suricata_threatbus.suricata:main"]
    },
    include_package_data=True,
    install_requires=[
        "black >= 19.10b",
        "dynaconf >= 3.1.4",
        "pyzmq >= 19",
        "parsuricata",
        "stix2 >= 3.0",
        "threatbus >= 2021.11.18",
    ],
    keywords=[
        "open source",
        "Suricata",
        "suricatasc",
        "IDS rules",
        "threatbus",
        "Threat Bus",
        "threat intelligence",
        "TI",
        "TI dissemination",
    ],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="suricata-threatbus",
    packages=["suricata_threatbus"],
    python_requires=">=3.7",
    setup_requires=["setuptools", "wheel"],
    url="https://github.com/tenzir/threatbus",
    version="2021.11.18",
)
