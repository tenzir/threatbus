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
    description="Bridges the gap between Threat Bus and STIX-Shifter",
    entry_points={
        "console_scripts": [
            "stix-shifter-threatbus=stix_shifter_threatbus.shifter:main"
        ]
    },
    include_package_data=True,
    install_requires=[
        "black >= 19.10b",
        "dynaconf >= 3.1.4",
        "python-dateutil",
        "pyzmq >= 19",
        "stix2 >= 3.0",
        "stix-shifter >= 3.4.2",
        "stix-shifter-utils >= 3.4.2",
        "threatbus >= 2021.11.18",
    ],
    keywords=[
        "open source",
        "threatbus",
        "Threat Bus",
        "threat intelligence",
        "TI",
        "TI dissemination",
    ],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="stix-shifter-threatbus",
    packages=["stix_shifter_threatbus"],
    python_requires=">=3.7",
    setup_requires=["setuptools", "wheel"],
    url="https://github.com/tenzir/threatbus",
    version="2021.11.18",
)
