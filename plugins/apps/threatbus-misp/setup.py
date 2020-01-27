from setuptools import setup

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
    description="A plugin to enable threatbus communication with MISP.",
    entry_points={"threatbus.app": ["misp = threatbus_misp"]},
    install_requires=[
        "threatbus>=0.3.0",
        "pymisp>=2.4.120",
        "pyzmq>=18.1.1",
        "confluent-kafka>=1.3.0",
    ],
    keywords=[
        "threatbus",
        "MISP",
        "threat intelligence",
        "IDS",
        "zeromq",
        "zmq",
        "kafka",
    ],
    license="BSD 3-clause",
    name="threatbus-misp",
    py_modules=["threatbus_misp", "misp_message_mapping"],
    python_requires=">=3.7",
    url="https://github.com/tenzir/threatbus",
    version="0.3.0",
)
