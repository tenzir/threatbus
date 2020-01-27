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
        "Topic :: Security",
        "Topic :: Software Development :: Object Brokering",
    ],
    description="A simplistic in-memory backbone for threatbus.",
    entry_points={"threatbus.backbone": ["inmem = threatbus_inmem"]},
    install_requires=["threatbus>=0.3.0",],
    keywords=["threatbus", "plugin"],
    license="BSD 3-clause",
    name="threatbus-inmem",
    py_modules=["threatbus_inmem"],
    python_requires=">=3.7",
    url="https://github.com/tenzir/threatbus",
    version="0.3.0",
)
