from setuptools import setup
import pathlib

plugin_dir = pathlib.Path(__file__).parent.absolute()

with open(f"{plugin_dir}/README.md", "r") as fh:
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
        "Programming Language :: Python :: 3",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
        "Topic :: Security",
        "Topic :: Software Development :: Object Brokering",
        "Topic :: System :: Distributed Computing",
    ],
    description="A plugin to enable threatbus communication with VAST.",
    entry_points={"threatbus.app": ["vast = threatbus_vast.plugin"]},
    install_requires=["threatbus>=2020.04.29", "pyzmq>=19", "pyvast>=2020.03.26",],
    keywords=["threatbus", "vast", "threat intelligence", "zeromq",],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="threatbus-vast",
    package_dir={"": "plugins/apps"},
    packages=["threatbus_vast"],
    python_requires=">=3.7",
    url="https://github.com/tenzir/threatbus",
    version="2020.06.25",
)
