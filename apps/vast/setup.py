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
    description="Connect the open source telemetry engine VAST with Threat Bus, the open source intelligence platform",
    entry_points={
        "console_scripts": ["pyvast-threatbus=pyvast_threatbus.pyvast_threatbus:main"]
    },
    include_package_data=True,
    install_requires=[
        "black>=19.10b",
        "coloredlogs>=14.0",
        "confuse",
        "pyzmq>=19",
        "pyvast>=2020.10.29",
        "threatbus>=2020.11.26",
        "unflatten",
    ],
    keywords=[
        "threatbus",
        "vast",
        "threat intelligence",
        "intel",
        "sightings",
        "open source threat intelligence",
        "intelligence platform",
    ],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="pyvast-threatbus",
    packages=["pyvast_threatbus"],
    python_requires=">=3.7",
    setup_requires=["setuptools", "wheel"],
    url="https://github.com/tenzir/threatbus",
    version="2020.11.26",
)
