from setuptools import setup

setup(
    name="threatbus-inmem",
    install_requires="threatbus",
    entry_points={"threatbus.backbone": ["inmem = threatbus_inmem"]},
    py_modules=["threatbus_inmem"],
    version="0.3.0",
)
