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
    install_requires=["pluggy>=0.3,<1.0", "confuse>=1.0", "coloredlogs>=10.0"],
    description="Connect open source threat intelligence tools",
    license="BSD 3-Clause license",
    include_package_data=True,
    packages=find_packages(),
    version="0.1.0",
    zip_safe=False,
    entry_points={"console_scripts": ["threatbus=threatbus.threatbus:main"]},
)
