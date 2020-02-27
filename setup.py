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
        "Environment :: Plugins",
        "License :: OSI Approved :: BSD License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
        "Topic :: Security",
        "Topic :: Software Development :: Object Brokering",
        "Topic :: System :: Distributed Computing",
    ],
    description="The missing link to connect open-source threat intelligence tools.",
    entry_points={"console_scripts": ["threatbus=threatbus.threatbus:main"]},
    include_package_data=True,
    install_requires=[
        "coloredlogs>=10.0",
        "confuse>=1.0",
        "pluggy>=0.13",
        "black>=19.10b",
    ],
    keywords=[
        "threatbus",
        "threat intelligence",
        "intel",
        "sightings",
        "open source threat intelligence",
    ],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="threatbus",
    packages=["threatbus"],
    python_requires=">=3.7",
    setup_requires=["setuptools", "wheel"],
    url="https://github.com/tenzir/threatbus",
    version="2020.02.27",
)
