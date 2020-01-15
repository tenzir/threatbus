from setuptools import setup

setup(
    name="threatbus-zeek",
    install_requires="threatbus",
    entry_points={"threatbus.app": ["zeek = threatbus_zeek"]},
    py_modules=["threatbus_zeek", "zeek_message_mapping"],
)
