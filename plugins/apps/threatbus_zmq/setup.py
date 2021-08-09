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
        "Development Status :: 4 - Beta",
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
    description="A plugin to connect apps via ZeroMQ.",
    entry_points={"threatbus.app": ["zmq = threatbus_zmq.plugin"]},
    install_requires=[
        "pyzmq>=19",
        "python-dateutil>=2.8.1",
        "stix2>=2.1,<3.0",
        "threatbus>=2021.5.27",
    ],
    keywords=[
        "zeromq",
        "zmq",
        "threatbus",
        "Threat Bus",
        "threat intelligence",
        "TI",
        "TI dissemination",
    ],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="threatbus-zmq",
    packages=["threatbus_zmq"],
    python_requires=">=3.7",
    url="https://github.com/tenzir/threatbus",
    version="2021.07.29",
)
