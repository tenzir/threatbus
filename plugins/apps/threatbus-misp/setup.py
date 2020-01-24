from setuptools import setup

setup(
    name="threatbus-misp",
    install_requires=[
        "threatbus>=0.2.0",
        "pymisp>=2.4.120",
        "pyzmq>=18.1.1",
        "confluent-kafka>=1.3.0",
    ],
    entry_points={"threatbus.app": ["misp = threatbus_misp"]},
    py_modules=["threatbus_misp", "misp_message_mapping"],
    version="0.3.0",
)
