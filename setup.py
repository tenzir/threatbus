#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    author="Tenzir",
    name="threatbus",
    author_email="engineering@tenzir.com",
    classifiers=[
        "License :: OSI Approved :: BSD 3-Clause",
        "Programming Language :: Python :: 3.8",
    ],
    install_requires=[
        "coloredlogs>=10.0",
        "confuse>=1.0",
        "pluggy>=0.13",
        "black>=19.10b",
    ],
    description="Connect open source threat intelligence tools",
    license="BSD 3-Clause license",
    include_package_data=True,
    packages=find_packages(),
    version="0.1.0",
    zip_safe=False,
    entry_points={"console_scripts": ["threatbus=threatbus.threatbus:main"]},
)
