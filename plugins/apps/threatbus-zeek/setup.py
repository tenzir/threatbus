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
    description="A plugin to enable threatbus communication with Zeek network monitor.",
    entry_points={"threatbus.app": ["zeek = threatbus_zeek"]},
    install_requires=["threatbus>=0.3.0",],
    keywords=["threatbus", "Zeek", "intrusion detection", "IDS", "broker", "plugin"],
    license="BSD 3-clause",
    name="threatbus-zeek",
    py_modules=["threatbus_zeek", "zeek_message_mapping"],
    python_requires=">=3.7",
    url="https://github.com/tenzir/threatbus",
    version="0.3.0",
)
